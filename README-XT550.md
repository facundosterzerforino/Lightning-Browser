# Navegador: Lightning 3.0.5 for Android 2.3 (branch `xt550-libre`)

This is Lightning Browser by Anthony Restaino (Apache 2.0) at upstream `c7d7752e`
(3.0.5b, January 2014), the last release that runs on Android 2.2/2.3. It is
built from source for a Motorola XT550 whose system Browser and Downloads apps
were removed.

## Changes

- **Removed the two prebuilt APKs** in the repository root (`BrowserActivity.apk`, `MainActivity.apk`).
- **Bookmarks page:** no longer loads each site's icon from
  `www.google.com/s2/favicons`, which told Google every saved bookmark.
- **Permissions:**
  - removed: location (`ACCESS_FINE_LOCATION`) and the old system browser's
    bookmarks (`READ/WRITE_HISTORY_BOOKMARKS`);
  - kept: Internet and the memory card;
  - geolocation is always off.
- **New "Descargas" screen** (menu → Descargas): lists the files this browser
  downloaded through Android's DownloadManager, with status and percentage.
  Tap opens a file; long-press deletes it. It also opens from the download
  notification and handles `VIEW_DOWNLOADS`. It needs no special permission,
  because an app always sees its own downloads.
- **No memory card:** a clear message instead of a silent failure (Android 2.3
  only downloads to the card).
- **Spanish:**
  - added the 64 Spanish texts missing upstream;
  - app name "Navegador" in Spanish.
- **Modern HTTPS (TLS 1.2/1.3)**: see the section below.
- **Certificate warnings**:
  - upstream silently accepted every certificate error except "untrusted"
    (for example a certificate for another site); now every unverified
    certificate asks first;
  - the warning is in Spanish.
- **Links for phone apps** (`meli://`, `intent://`…): the browser opens the app
  if it is installed; otherwise it ignores the link instead of showing
  "Página web no disponible".
- **Build:** `build.py` builds offline with aapt, javac, D8 and apksigner
  against the API 17 `android.jar`, plus NDK r10e for the TLS library
  (`jni/build_native.py`, GCC 4.9, android-9, armeabi-v7a).

## Review

- No analytics, ads, crash reporters or device identifiers.
- No command execution or dynamic code loading.
- The only built-in network addresses are the search engines and the default
  homepage (Google), plus links in Settings.

## Modern HTTPS on Android 2.3

Android 2.3's WebView makes its HTTPS connections with the system's OpenSSL 1.0.0a:
TLS 1.0 and a 2012 root list. Most sites refuse it ("Página web no disponible").
This browser brings its own TLS, only for itself:

1. **Library.** `third_party/mbedtls` is mbedTLS 3.6.7 (Apache 2.0). The
   `library/` and `include/` folders are unchanged from the official release
   archive, SHA256 `a7e8bcbe…11f6`, as published on its GitHub release.
   `jni/mbedtls_xt550_config.h`:
   - client only, with threading;
   - uses `/dev/urandom`: this phone's 2.6.38 kernel has no `getrandom()`, and
     mbedTLS 3.6's fallback `/dev/random` blocked for 235 s.
2. **Roots.** `assets/roots.pem` holds the 110 roots Mozilla trusts for
   websites. `tools/make_roots.py` generates it from Mozilla's `certdata.txt`
   (SHA256 `358dd0db…39c6`, `mozilla-central` tip, November 2026), keeping only
   `CKA_TRUST_SERVER_AUTH = CKT_NSS_TRUSTED_DELEGATOR` and dropping roots whose
   server distrust date has passed. Cross-checked against curl's `cacert.pem`:
   all 110 are there.
3. **Socket.** `jni/moderntls.c` (JNI) plus `tls/ModernSSLSocket` implement an
   `SSLSocket`:
   - Java owns the TCP socket; mbedTLS works on memory buffers;
   - the chain AND the host name are verified (`VERIFY_REQUIRED`), or the
     handshake fails;
   - sessions are resumed: TLS 1.2 sessions and TLS 1.3 tickets, in memory
     only;
   - one full handshake per site at a time, so the other connections resume
     its session instead of doing 8 full handshakes at once on a slow CPU;
   - a 30 s connect timeout (Android 2.3 has none).
4. **Hook.** `tls/ModernTls.install()` runs at startup:
   - it sets the static `android.net.http.HttpsConnection.mSslSocketFactory`
     by reflection, for this app's process only;
   - this field is present in this phone's Motorola framework (checked in
     `framework.odex`).
5. **Old validator.** Android's own validator still checks the chain against
   its 2012 roots and raises an `SslError` for sites it doesn't know.
   `onReceivedSslError` proceeds **only** if that certificate is one mbedTLS
   just verified. Anything else shows the warning.
6. **Switch.** Ajustes avanzados → "HTTPS moderno (TLS 1.3)" (on by default).
   Turning it off restores Android's factory.

What it does not fix: the 2010 rendering engine and JavaScript. Some sites block
the old browser (Clarín: "you have been blocked") or refuse it (YouTube: "Tu
dispositivo ya no es compatible").

## Tested on the XT550 (Android 2.3.6)

- **HTTPS that works:**
  - Google, Wikipedia (desktop and mobile with images), DuckDuckGo HTML, La
    Nación, argentina.gob.ar, CNN Lite, MercadoLibre and badssl.com all load;
  - with TLS 1.3, or TLS 1.2 where the site only offers that;
  - about 80 connections in those tests, none failed.
- **Bad certificates are rejected** (badssl.com expired, wrong host,
  untrusted root): the page shows "Página web no disponible" and the log gives
  the reason.
- **Speed on the 600 MHz Cortex-A5:**
  - full handshake about 0.4–0.5 s;
  - resumed handshake 0.1–0.3 s alone, up to about 1.3 s when the page opens
    eight connections at once;
  - the library and root list load in about 0.1 s.
- **Memory:** no measurable difference with the switch on or off (PSS with the
  same page: 39–42 MB both ways; the noise is about 2 MB).
- The menu is in Spanish; Descargas lists, deletes, and shows the no-card message.
