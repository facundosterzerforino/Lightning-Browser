/* xt550-libre: mbedTLS 3.6 settings for the browser's TLS client.
 * Applied on top of mbedTLS's default mbedtls_config.h. */

/* WebView opens several HTTPS connections from different threads. */
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_PTHREAD

/* Kernel 2.6.38 (this phone) has no getrandom(), so mbedTLS 3.6 falls back to /dev/random,
 * which on this old kernel blocks for minutes (measured: 235 s for the first
 * 64 bytes). /dev/urandom is what Android's own SecureRandom reads; the pool is
 * long seeded by the time the user opens the browser. */
#define MBEDTLS_PLATFORM_DEV_RANDOM "/dev/urandom"

/* Client only: drop the server side and DTLS. */
#undef MBEDTLS_SSL_SRV_C
#undef MBEDTLS_SSL_PROTO_DTLS
#undef MBEDTLS_SSL_DTLS_ANTI_REPLAY
#undef MBEDTLS_SSL_DTLS_HELLO_VERIFY
#undef MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE
#undef MBEDTLS_SSL_DTLS_CONNECTION_ID
#undef MBEDTLS_SSL_DTLS_SRTP
#undef MBEDTLS_SSL_COOKIE_C
#undef MBEDTLS_SSL_TICKET_C

/* Java owns the sockets; no files, no timers, no self tests. */
#undef MBEDTLS_NET_C
#undef MBEDTLS_TIMING_C
#undef MBEDTLS_FS_IO
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_SELF_TEST
