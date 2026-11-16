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
- **Build:** `build.py` builds offline with aapt, javac, D8 and apksigner
  against the API 17 `android.jar`.

## Review

- No analytics, ads, crash reporters or device identifiers.
- No command execution or dynamic code loading.
- The only built-in network addresses are the search engines and the default
  homepage (Google), plus links in Settings.

## Known limit (Android 2.3, not this app)

The Android 2.3 WebView only supports old TLS versions. On the test phone,
plain `http://` sites and `https://www.google.com` load. Most other `https://`
sites (Wikipedia, DuckDuckGo, Bing, newspapers, government) show "Página web no
disponible". Every WebView browser on Android 2.3 has this limit.

## Tested on the XT550 (Android 2.3.6)

- Pages load as described above.
- The menu is in Spanish; Descargas lists, deletes, and shows the no-card message.
- RAM: about 14.5 MB PSS with a page open.
