package acr.browser.barebones.tls;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.security.cert.X509Certificate;
import java.util.LinkedList;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import android.content.Context;
import android.net.http.SslCertificate;
import android.net.http.SslError;
import android.util.Log;

/**
 * Modern HTTPS for the Android 2.3 WebView.
 *
 * Gingerbread's WebView opens every HTTPS connection through the static
 * android.net.http.HttpsConnection.mSslSocketFactory (OpenSSL 1.0.0a: TLS 1.0
 * and 2012 roots, so most sites fail). install() replaces that factory, for
 * this app's process only, with one backed by mbedTLS (TLS 1.2/1.3, Mozilla's
 * current roots, host name check). A connection exists only if mbedTLS
 * verified the site.
 *
 * Android's old validator then re-checks the chain against its 2012 roots and
 * raises an SslError for sites it doesn't know. {@link #verifiedByUs} lets the
 * WebViewClient proceed ONLY when the certificate in that error is one that
 * mbedTLS has just verified; anything else still shows the warning.
 *
 * Turned off with the "modernTls" setting; nothing outside this app changes.
 */
public final class ModernTls {
	public static final String PREF = "modernTls";
	private static final String TAG = "ModernTls";
	private static final int REMEMBER = 128;

	private static boolean sReady;
	private static Field sField;
	private static SSLSocketFactory sFactory;
	private static Object sOriginal;
	private static final LinkedList<String> sVerified = new LinkedList<String>();
	private static final java.util.HashMap<String, Long> sFirst = new java.util.HashMap<String, Long>();
	private static final java.util.HashSet<String> sResumable = new java.util.HashSet<String>();
	private static final long FIRST_WAIT_MS = 4000;

	private ModernTls() {
	}

	/** Loads mbedTLS + roots and swaps the WebView socket factory. Safe to call often. */
	public static synchronized boolean install(Context context) {
		if (!context.getSharedPreferences("settings", 0).getBoolean(PREF, true)) {
			uninstall();
			return false;
		}
		if (sReady) {
			ensure();
			return true;
		}
		try {
			long start = System.currentTimeMillis();
			System.loadLibrary("moderntls");
			int roots = NativeTls.init(readAsset(context, "roots.pem"));
			if (roots <= 0) {
				Log.e(TAG, "root list failed: " + NativeTls.errorString(roots));
				return false;
			}
			sFactory = new ModernSSLSocketFactory();
			Class<?> c = Class.forName("android.net.http.HttpsConnection");
			sField = c.getDeclaredField("mSslSocketFactory");
			sField.setAccessible(true);
			synchronized (c) {
				sOriginal = sField.get(null);
				sField.set(null, sFactory);
			}
			HttpsURLConnection.setDefaultSSLSocketFactory(sFactory);
			sReady = true;
			Log.i(TAG, "installed: " + roots + " roots, "
					+ (System.currentTimeMillis() - start) + " ms");
			return true;
		} catch (Throwable t) {
			Log.e(TAG, "cannot install modern TLS, keeping Android's", t);
			sReady = false;
			return false;
		}
	}

	/** Puts the factory back if Android replaced it (e.g. re-initialised the engine). */
	public static synchronized void ensure() {
		if (!sReady) {
			return;
		}
		try {
			if (sField.get(null) != sFactory) {
				Log.w(TAG, "WebView socket factory was replaced; restoring ours");
				synchronized (sField.getDeclaringClass()) {
					sField.set(null, sFactory);
				}
			}
		} catch (Throwable t) {
			Log.e(TAG, "ensure failed", t);
		}
	}

	/** Restores Android's own factory (setting turned off). */
	public static synchronized void uninstall() {
		if (!sReady) {
			return;
		}
		try {
			synchronized (sField.getDeclaringClass()) {
				sField.set(null, sOriginal);
			}
			HttpsURLConnection.setDefaultSSLSocketFactory((SSLSocketFactory) sOriginal);
		} catch (Throwable t) {
			Log.e(TAG, "uninstall failed", t);
		}
		sReady = false;
		synchronized (sVerified) {
			sVerified.clear();
		}
		Log.i(TAG, "uninstalled");
	}

	/**
	 * Returns key if the caller does the site's first full handshake (it must
	 * then call firstHandshakeDone), or null after waiting for another thread's
	 * first handshake (up to 4 s) so that this one can resume its session.
	 */
	static String awaitFirstHandshake(String key) {
		synchronized (sFirst) {
			if (sResumable.contains(key)) {
				return null;
			}
			long deadline = System.currentTimeMillis() + FIRST_WAIT_MS;
			while (sFirst.containsKey(key)) {
				long left = deadline - System.currentTimeMillis();
				if (left <= 0) {
					return null;
				}
				try {
					sFirst.wait(left);
				} catch (InterruptedException e) {
					return null;
				}
			}
			if (sResumable.contains(key)) {
				return null;
			}
			sFirst.put(key, System.currentTimeMillis());
			return key;
		}
	}

	static void firstHandshakeDone(String key) {
		synchronized (sFirst) {
			sFirst.remove(key);
			if (sResumable.size() > 200) {
				sResumable.clear();
			}
			sResumable.add(key);
			sFirst.notifyAll();
		}
	}

	static boolean ready() {
		return sReady;
	}

	/** Called by ModernSSLSocket after mbedTLS verified chain + host name. */
	static void rememberVerified(X509Certificate leaf) {
		String k = key(new SslCertificate(leaf));
		synchronized (sVerified) {
			sVerified.remove(k);
			sVerified.addFirst(k);
			while (sVerified.size() > REMEMBER) {
				sVerified.removeLast();
			}
		}
	}

	/** True if the certificate in this SslError was verified by mbedTLS. */
	public static boolean verifiedByUs(SslError error) {
		if (!sReady || error == null || error.getCertificate() == null) {
			return false;
		}
		String k = key(error.getCertificate());
		synchronized (sVerified) {
			boolean ok = sVerified.contains(k);
			if (!ok) {
				Log.w(TAG, "SslError " + error.getPrimaryError() + " for a certificate we did not verify");
			}
			return ok;
		}
	}

	private static String key(SslCertificate c) {
		return c.getIssuedTo().getDName() + "\n" + c.getIssuedBy().getDName() + "\n"
				+ c.getValidNotBeforeDate().getTime() + "\n" + c.getValidNotAfterDate().getTime();
	}

	private static byte[] readAsset(Context context, String name) throws java.io.IOException {
		InputStream in = context.getAssets().open(name);
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream(200 * 1024);
			byte[] b = new byte[8192];
			int n;
			while ((n = in.read(b)) > 0) {
				out.write(b, 0, n);
			}
			return out.toByteArray();
		} finally {
			in.close();
		}
	}
}
