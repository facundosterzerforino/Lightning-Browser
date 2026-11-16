package acr.browser.barebones.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.concurrent.locks.ReentrantLock;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;

import android.util.Log;

/**
 * An SSLSocket whose TLS runs in mbedTLS (TLS 1.2/1.3, Mozilla roots, host
 * name checked). The handshake fails unless the server proves it is the real
 * site, so Android 2.3's old validator only ever sees verified connections.
 *
 * Plain mode: this object is itself the TCP socket (created unconnected, then
 * connect()). Layered mode: TLS runs over an already connected socket (proxy
 * tunnel).
 */
final class ModernSSLSocket extends SSLSocket {
	private static final String TAG = "ModernTls";
	private static final String[] SUITES = { "TLS_MBEDTLS_DEFAULT" };
	private static final String[] PROTOCOLS = { "TLSv1.2", "TLSv1.3" };

	private final Socket mLayered;
	private final boolean mAutoClose;
	private String mHost;
	private int mPort;

	private final ReentrantLock mLock = new ReentrantLock();
	private long mCtx;
	private boolean mHandshakeDone;
	private IOException mHandshakeError;
	private volatile boolean mClosed;
	private Session mSession;
	private InputStream mRawIn;
	private OutputStream mRawOut;
	private final byte[] mRawBuf = new byte[17 * 1024];
	private final In mIn = new In();
	private final Out mOut = new Out();

	ModernSSLSocket() {
		super();
		mLayered = null;
		mAutoClose = true;
	}

	ModernSSLSocket(Socket layered, String host, int port, boolean autoClose) {
		super();
		mLayered = layered;
		mHost = host;
		mPort = port;
		mAutoClose = autoClose;
	}

	// ---------------------------------------------------------------- TCP

	/** Android 2.3 connects with no time limit; an unreachable server would spin forever. */
	private static final int CONNECT_TIMEOUT_MS = 30 * 1000;

	@Override
	public void connect(SocketAddress a, int timeout) throws IOException {
		if (timeout == 0) {
			timeout = CONNECT_TIMEOUT_MS;
		}
		if (a instanceof InetSocketAddress) {
			InetSocketAddress i = (InetSocketAddress) a;
			if (mHost == null) {
				mHost = i.getHostName();
			}
			mPort = i.getPort();
		}
		super.connect(a, timeout);
	}

	private void ensureRaw() throws IOException {
		if (mRawIn == null) {
			if (mLayered != null) {
				mRawIn = mLayered.getInputStream();
				mRawOut = mLayered.getOutputStream();
			} else {
				mRawIn = super.getInputStream();
				mRawOut = super.getOutputStream();
			}
		}
	}

	/** Sends whatever mbedTLS produced. Caller holds mLock. */
	static final boolean TRACE = false; // per-read/write debug log

	private void trace(String s) {
		if (TRACE) {
			Log.d(TAG, mHost + "#" + Integer.toHexString(System.identityHashCode(this)) + " "
					+ Thread.currentThread().getName() + ": " + s);
		}
	}

	private void flushOut() throws IOException {
		byte[] o = NativeTls.takeOutput(mCtx);
		if (o != null) {
			trace("send " + o.length);
			mRawOut.write(o);
			mRawOut.flush();
		}
	}

	/** Reads network bytes into mbedTLS. Returns -1 at end of stream. Caller holds mLock. */
	private int pump() throws IOException {
		trace("pump wait");
		int n = mRawIn.read(mRawBuf);
		trace("pump got " + n);
		if (n < 0) {
			NativeTls.feed(mCtx, null, 0, -1);
		} else if (n > 0) {
			NativeTls.feed(mCtx, mRawBuf, 0, n);
		}
		return n;
	}

	// ---------------------------------------------------------- handshake

	@Override
	public void startHandshake() throws IOException {
		mLock.lock();
		try {
			if (mHandshakeDone) {
				return;
			}
			if (mHandshakeError != null) {
				throw mHandshakeError;
			}
			try {
				doHandshake();
				mHandshakeDone = true;
			} catch (IOException e) {
				releaseGate();
				mHandshakeError = e;
				Log.w(TAG, "handshake failed: " + e.getMessage());
				throw e;
			}
		} finally {
			mLock.unlock();
		}
	}

	private void doHandshake() throws IOException {
		if (mClosed) {
			throw new SocketException("Socket is closed");
		}
		if (mHost == null) {
			throw new SSLHandshakeException("no host name for TLS");
		}
		if (!ModernTls.ready()) {
			throw new SSLHandshakeException("modern TLS not loaded");
		}
		ensureRaw();
		long start = System.currentTimeMillis();
		// One full handshake per site at a time: the others wait for its session
		// and resume it (the CPU is too slow for 8 parallel full handshakes).
		String key = mHost + ":" + (mPort > 0 ? mPort : 443);
		mGateKey = ModernTls.awaitFirstHandshake(key);
		long c = NativeTls.open(mHost, mPort > 0 ? mPort : 443);
		if (c <= 0) {
			throw new SSLHandshakeException(mHost + ": " + NativeTls.errorString((int) c));
		}
		mCtx = c;
		while (true) {
			int r = NativeTls.handshake(mCtx);
			flushOut();
			if (r == 0) {
				break;
			}
			if (r == NativeTls.WANT_READ) {
				pump();
				continue;
			}
			String why = NativeTls.verifyInfo(mCtx);
			throw new SSLHandshakeException(mHost + ": " + NativeTls.errorString(r)
					+ (why != null ? " (" + why.trim() + ")" : ""));
		}
		if (mGateKey != null && mSessionTicketsArriveLater()) {
			// TLS 1.3: the ticket comes with the first data; release on first read.
		} else {
			releaseGate();
		}
		X509Certificate[] chain = parseChain(NativeTls.peerChain(mCtx));
		mSession = new Session(mHost, mPort, chain, NativeTls.info(mCtx));
		ModernTls.rememberVerified(chain[0]);
		Log.i(TAG, mHost + ": " + mSession.mInfo
				+ (NativeTls.resumed(mCtx) == 1 ? " (resumed)" : "") + ", "
				+ (System.currentTimeMillis() - start) + " ms");
	}

	private String mGateKey;

	private boolean mSessionTicketsArriveLater() {
		String info = NativeTls.info(mCtx);
		return info != null && info.startsWith("TLSv1.3");
	}

	private void releaseGate() {
		if (mGateKey != null) {
			ModernTls.firstHandshakeDone(mGateKey);
			mGateKey = null;
		}
	}

	private X509Certificate[] parseChain(byte[][] ders) throws IOException {
		ArrayList<X509Certificate> list = new ArrayList<X509Certificate>();
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			for (int i = 0; ders != null && i < ders.length; i++) {
				try {
					list.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(ders[i])));
				} catch (Exception e) {
					if (i == 0) {
						throw e;
					}
					Log.w(TAG, mHost + ": skipping certificate " + i + ": " + e);
				}
			}
		} catch (Exception e) {
			throw new SSLHandshakeException(mHost + ": Android cannot read the certificate: " + e);
		}
		if (list.isEmpty()) {
			throw new SSLHandshakeException(mHost + ": no certificate");
		}
		return list.toArray(new X509Certificate[list.size()]);
	}

	@Override
	public SSLSession getSession() {
		trace("getSession");
		try {
			startHandshake();
			return mSession;
		} catch (IOException e) {
			return new Session(mHost, mPort, null, null);
		}
	}

	// ------------------------------------------------------------ streams

	@Override
	public InputStream getInputStream() throws IOException {
		if (mClosed) {
			throw new SocketException("Socket is closed");
		}
		return mIn;
	}

	@Override
	public OutputStream getOutputStream() throws IOException {
		if (mClosed) {
			throw new SocketException("Socket is closed");
		}
		return mOut;
	}

	private final class In extends InputStream {
		@Override
		public int read() throws IOException {
			byte[] b = new byte[1];
			int n = read(b, 0, 1);
			return n <= 0 ? -1 : (b[0] & 0xff);
		}

		@Override
		public int read(byte[] b, int off, int len) throws IOException {
			if (len == 0) {
				return 0;
			}
			startHandshake();
			mLock.lock();
			try {
				while (true) {
					if (mClosed || mCtx == 0) {
						throw new SocketException("Socket is closed");
					}
					int r = NativeTls.read(mCtx, b, off, len);
					trace("app read(" + len + ") = " + r);
					if (r > 0) {
						releaseGate();
						return r;
					}
					if (r == NativeTls.EOF) {
						releaseGate();
						return -1;
					}
					if (r == NativeTls.WANT_READ) {
						flushOut();
						pump();
						continue;
					}
					throw new SSLException(mHost + ": " + NativeTls.errorString(r));
				}
			} finally {
				mLock.unlock();
			}
		}

		@Override
		public void close() throws IOException {
			ModernSSLSocket.this.close();
		}
	}

	private final class Out extends OutputStream {
		@Override
		public void write(int b) throws IOException {
			write(new byte[] { (byte) b }, 0, 1);
		}

		@Override
		public void write(byte[] b, int off, int len) throws IOException {
			startHandshake();
			mLock.lock();
			try {
				while (len > 0) {
					if (mClosed || mCtx == 0) {
						throw new SocketException("Socket is closed");
					}
					int r = NativeTls.write(mCtx, b, off, len);
					trace("app write(" + len + ") = " + r);
					if (r > 0) {
						off += r;
						len -= r;
						flushOut();
					} else if (r == NativeTls.WANT_READ) {
						flushOut();
						if (pump() < 0) {
							throw new SocketException("connection closed");
						}
					} else {
						throw new SSLException(mHost + ": " + NativeTls.errorString(r));
					}
				}
			} finally {
				mLock.unlock();
			}
		}

		@Override
		public void flush() throws IOException {
			if (mRawOut != null) {
				mRawOut.flush();
			}
		}

		@Override
		public void close() throws IOException {
			ModernSSLSocket.this.close();
		}
	}

	// -------------------------------------------------------------- close

	@Override
	public void close() throws IOException {
		trace("close");
		synchronized (this) {
			if (mClosed) {
				return;
			}
			mClosed = true;
		}
		releaseGate();
		// Polite close_notify only if no other thread is inside a read/write.
		if (mLock.tryLock()) {
			try {
				if (mCtx != 0 && mHandshakeDone) {
					NativeTls.closeNotify(mCtx);
					try {
						flushOut();
					} catch (IOException ignored) {
						// the peer may already be gone
					}
				}
			} finally {
				mLock.unlock();
			}
		}
		try {
			if (mLayered != null) {
				if (mAutoClose) {
					mLayered.close();
				}
			} else {
				super.close();
			}
		} finally {
			mLock.lock(); // a blocked read/write ends once the socket is closed
			try {
				if (mCtx != 0) {
					NativeTls.free(mCtx);
					mCtx = 0;
				}
			} finally {
				mLock.unlock();
			}
		}
	}

	@Override
	protected void finalize() throws Throwable {
		try {
			close();
		} finally {
			super.finalize();
		}
	}

	// ------------------------------------- layered mode: delegate to TCP

	@Override
	public boolean isConnected() {
		return mLayered != null ? mLayered.isConnected() : super.isConnected();
	}

	@Override
	public boolean isClosed() {
		return mClosed || (mLayered != null ? mLayered.isClosed() : super.isClosed());
	}

	@Override
	public InetAddress getInetAddress() {
		return mLayered != null ? mLayered.getInetAddress() : super.getInetAddress();
	}

	@Override
	public int getPort() {
		return mLayered != null ? mLayered.getPort() : super.getPort();
	}

	@Override
	public InetAddress getLocalAddress() {
		return mLayered != null ? mLayered.getLocalAddress() : super.getLocalAddress();
	}

	@Override
	public int getLocalPort() {
		return mLayered != null ? mLayered.getLocalPort() : super.getLocalPort();
	}

	@Override
	public SocketAddress getRemoteSocketAddress() {
		return mLayered != null ? mLayered.getRemoteSocketAddress() : super.getRemoteSocketAddress();
	}

	@Override
	public synchronized void setSoTimeout(int timeout) throws SocketException {
		if (mLayered != null) {
			mLayered.setSoTimeout(timeout);
		} else {
			super.setSoTimeout(timeout);
		}
	}

	@Override
	public synchronized int getSoTimeout() throws SocketException {
		return mLayered != null ? mLayered.getSoTimeout() : super.getSoTimeout();
	}

	@Override
	public void setTcpNoDelay(boolean on) throws SocketException {
		if (mLayered != null) {
			mLayered.setTcpNoDelay(on);
		} else {
			super.setTcpNoDelay(on);
		}
	}

	@Override
	public void setSoLinger(boolean on, int linger) throws SocketException {
		if (mLayered != null) {
			mLayered.setSoLinger(on, linger);
		} else {
			super.setSoLinger(on, linger);
		}
	}

	@Override
	public void setKeepAlive(boolean on) throws SocketException {
		if (mLayered != null) {
			mLayered.setKeepAlive(on);
		} else {
			super.setKeepAlive(on);
		}
	}

	@Override
	public void shutdownInput() throws IOException {
		throw new UnsupportedOperationException("not supported on TLS sockets");
	}

	@Override
	public void shutdownOutput() throws IOException {
		throw new UnsupportedOperationException("not supported on TLS sockets");
	}

	// ----------------------------------------------- SSLSocket boilerplate

	@Override
	public String[] getSupportedCipherSuites() {
		return SUITES.clone();
	}

	@Override
	public String[] getEnabledCipherSuites() {
		return SUITES.clone();
	}

	@Override
	public void setEnabledCipherSuites(String[] suites) {
		// mbedTLS defaults are used
	}

	@Override
	public String[] getSupportedProtocols() {
		return PROTOCOLS.clone();
	}

	@Override
	public String[] getEnabledProtocols() {
		return PROTOCOLS.clone();
	}

	@Override
	public void setEnabledProtocols(String[] protocols) {
		// TLS 1.2 and 1.3 only
	}

	@Override
	public void addHandshakeCompletedListener(HandshakeCompletedListener l) {
	}

	@Override
	public void removeHandshakeCompletedListener(HandshakeCompletedListener l) {
	}

	@Override
	public void setUseClientMode(boolean mode) {
		if (!mode) {
			throw new IllegalArgumentException("client mode only");
		}
	}

	@Override
	public boolean getUseClientMode() {
		return true;
	}

	@Override
	public void setNeedClientAuth(boolean need) {
	}

	@Override
	public boolean getNeedClientAuth() {
		return false;
	}

	@Override
	public void setWantClientAuth(boolean want) {
	}

	@Override
	public boolean getWantClientAuth() {
		return false;
	}

	@Override
	public void setEnableSessionCreation(boolean flag) {
	}

	@Override
	public boolean getEnableSessionCreation() {
		return true;
	}

	// -------------------------------------------------------------- session

	static final class Session implements SSLSession {
		final String mHost;
		final int mPort;
		final X509Certificate[] mChain;
		final String mInfo;
		final long mCreated = System.currentTimeMillis();
		private boolean mInvalidated;

		Session(String host, int port, X509Certificate[] chain, String info) {
			mHost = host;
			mPort = port;
			mChain = chain;
			mInfo = info;
		}

		public boolean isValid() {
			return mChain != null && !mInvalidated;
		}

		public void invalidate() {
			mInvalidated = true;
		}

		public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
			if (mChain == null) {
				throw new SSLPeerUnverifiedException("handshake failed");
			}
			return mChain.clone();
		}

		public javax.security.cert.X509Certificate[] getPeerCertificateChain()
				throws SSLPeerUnverifiedException {
			throw new SSLPeerUnverifiedException("not available");
		}

		public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
			if (mChain == null) {
				throw new SSLPeerUnverifiedException("handshake failed");
			}
			return mChain[0].getSubjectX500Principal();
		}

		public Certificate[] getLocalCertificates() {
			return null;
		}

		public Principal getLocalPrincipal() {
			return null;
		}

		public String getCipherSuite() {
			return mInfo == null ? "SSL_NULL_WITH_NULL_NULL" : mInfo.substring(mInfo.indexOf(' ') + 1);
		}

		public String getProtocol() {
			return mInfo == null ? "NONE" : mInfo.substring(0, mInfo.indexOf(' '));
		}

		public String getPeerHost() {
			return mHost;
		}

		public int getPeerPort() {
			return mPort;
		}

		public byte[] getId() {
			return new byte[0];
		}

		public long getCreationTime() {
			return mCreated;
		}

		public long getLastAccessedTime() {
			return mCreated;
		}

		public SSLSessionContext getSessionContext() {
			return null;
		}

		public int getApplicationBufferSize() {
			return 16384;
		}

		public int getPacketBufferSize() {
			return 16384 + 2048;
		}

		public Object getValue(String name) {
			return null;
		}

		public String[] getValueNames() {
			return new String[0];
		}

		public void putValue(String name, Object value) {
		}

		public void removeValue(String name) {
		}
	}
}
