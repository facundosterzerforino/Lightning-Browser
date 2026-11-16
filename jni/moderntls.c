/*
 * Modern TLS (1.2/1.3) for the Lightning browser on Android 2.3, using mbedTLS.
 *
 * Java owns the TCP socket. This file only encrypts/decrypts through two memory
 * buffers: Java feeds bytes read from the network with feed(), and sends what
 * takeOutput() returns. The server certificate chain AND the host name are
 * verified here (MBEDTLS_SSL_VERIFY_REQUIRED against the bundled Mozilla roots),
 * so a handshake only succeeds for the genuine site.
 */
#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <android/log.h>

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
#include "psa/crypto.h"

#define TAG "ModernTls"
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)

/* Return codes shared with NativeTls.java (outside mbedTLS's error range). */
#define RET_EOF (-0x10001)
#define RET_WANT_READ (-0x10002)
#define RET_NOT_READY (-0x10003)
#define RET_NO_MEMORY (-0x10004)

typedef struct {
    unsigned char *buf;
    size_t len, cap, pos;
} bbuf;

typedef struct {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    bbuf in, out;
    int eof;
    char key[300];      /* "host:port" for the session cache */
    int offered;        /* a cached session was offered */
} conn;

/* ---- session resumption cache ------------------------------------------
 * After a fully verified handshake the TLS session (TLS 1.2 session/ticket or
 * TLS 1.3 ticket) is saved per host:port, together with the certificate chain
 * that was verified then. Later connections to the same site resume it and
 * skip the expensive certificate checks. Kept in memory only. */
#define CACHE_SIZE 24
typedef struct {
    char key[300];
    unsigned char *session;
    size_t session_len;
    unsigned char *chain;   /* concatenated: 4-byte big-endian length + DER */
    size_t chain_len;
    unsigned long used;
} cache_entry;
static cache_entry g_cache[CACHE_SIZE];
static unsigned long g_cache_clock = 0;
static pthread_mutex_t g_cache_lock = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static mbedtls_x509_crt g_roots;
static int g_roots_count = 0;

static int bb_append(bbuf *b, const unsigned char *d, size_t n)
{
    if (b->pos > 0) {
        memmove(b->buf, b->buf + b->pos, b->len - b->pos);
        b->len -= b->pos;
        b->pos = 0;
    }
    if (b->len + n > b->cap) {
        size_t cap = b->cap ? b->cap : 4096;
        unsigned char *p;
        while (cap < b->len + n) cap *= 2;
        p = realloc(b->buf, cap);
        if (p == NULL) return -1;
        b->buf = p;
        b->cap = cap;
    }
    memcpy(b->buf + b->len, d, n);
    b->len += n;
    return 0;
}

static int bio_send(void *ctx, const unsigned char *d, size_t n)
{
    conn *c = (conn *) ctx;
    if (bb_append(&c->out, d, n) != 0) return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    return (int) n;
}

static int bio_recv(void *ctx, unsigned char *d, size_t n)
{
    conn *c = (conn *) ctx;
    size_t avail = c->in.len - c->in.pos;
    if (avail == 0) return c->eof ? 0 : MBEDTLS_ERR_SSL_WANT_READ;
    if (n > avail) n = avail;
    memcpy(d, c->in.buf + c->in.pos, n);
    c->in.pos += n;
    if (c->in.pos == c->in.len) c->in.pos = c->in.len = 0;
    return (int) n;
}

static conn *C(jlong p) { return (conn *) (uintptr_t) p; }

/* True if mbedTLS can still make progress without new network bytes: our input
 * buffer is not empty or mbedTLS holds an unprocessed record. After a TLS 1.3
 * NewSessionTicket mbedTLS may answer WANT_READ although the HTTP response is
 * already buffered; returning WANT_READ then makes Java block on a socket the
 * server will not write to again (keep-alive), so the page hangs. */
static int can_progress(conn *c)
{
    return c->in.len > c->in.pos || mbedtls_ssl_check_pending(&c->ssl);
}

static cache_entry *cache_find(const char *key)
{
    int i;
    for (i = 0; i < CACHE_SIZE; i++)
        if (g_cache[i].session != NULL && strcmp(g_cache[i].key, key) == 0) return &g_cache[i];
    return NULL;
}

static void cache_drop(cache_entry *e)
{
    free(e->session);
    free(e->chain);
    memset(e, 0, sizeof(*e));
}

/* Serialises the peer chain currently held by the connection (full handshakes). */
static unsigned char *chain_blob(const mbedtls_ssl_context *ssl, size_t *len)
{
    const mbedtls_x509_crt *crt = mbedtls_ssl_get_peer_cert(ssl), *q;
    size_t n = 0;
    unsigned char *b, *w;
    for (q = crt; q != NULL && q->raw.len > 0; q = q->next) n += 4 + q->raw.len;
    *len = 0;
    if (n == 0) return NULL;
    b = w = malloc(n);
    if (b == NULL) return NULL;
    for (q = crt; q != NULL && q->raw.len > 0; q = q->next) {
        w[0] = (unsigned char) (q->raw.len >> 24); w[1] = (unsigned char) (q->raw.len >> 16);
        w[2] = (unsigned char) (q->raw.len >> 8); w[3] = (unsigned char) q->raw.len;
        memcpy(w + 4, q->raw.p, q->raw.len);
        w += 4 + q->raw.len;
    }
    *len = n;
    return b;
}

/* Saves the connection's session for its host (call after a verified handshake
 * or after a TLS 1.3 NewSessionTicket). */
static void cache_store(conn *c)
{
    mbedtls_ssl_session sess;
    size_t len = 0;
    unsigned char *buf, *chain;
    size_t chain_len;
    cache_entry *e;
    int i;
    mbedtls_ssl_session_init(&sess);
    if (mbedtls_ssl_get_session(&c->ssl, &sess) != 0) {
        mbedtls_ssl_session_free(&sess);
        return;
    }
    mbedtls_ssl_session_save(&sess, NULL, 0, &len);
    buf = len ? malloc(len) : NULL;
    if (buf == NULL || mbedtls_ssl_session_save(&sess, buf, len, &len) != 0) {
        free(buf);
        mbedtls_ssl_session_free(&sess);
        return;
    }
    mbedtls_ssl_session_free(&sess);
    chain = chain_blob(&c->ssl, &chain_len);
    pthread_mutex_lock(&g_cache_lock);
    e = cache_find(c->key);
    if (e != NULL && chain == NULL) {
        /* resumed connection: keep the chain verified by the full handshake */
        chain = e->chain;
        chain_len = e->chain_len;
        e->chain = NULL;
    }
    if (chain == NULL) {
        pthread_mutex_unlock(&g_cache_lock);
        free(buf);
        return;
    }
    if (e == NULL) {
        e = &g_cache[0];
        for (i = 0; i < CACHE_SIZE; i++) {
            if (g_cache[i].session == NULL) { e = &g_cache[i]; break; }
            if (g_cache[i].used < e->used) e = &g_cache[i];
        }
    }
    cache_drop(e);
    strncpy(e->key, c->key, sizeof(e->key) - 1);
    e->session = buf;
    e->session_len = len;
    e->chain = chain;
    e->chain_len = chain_len;
    e->used = ++g_cache_clock;
    pthread_mutex_unlock(&g_cache_lock);
}

#define JFN(name) Java_acr_browser_barebones_tls_NativeTls_##name

/* Parses the PEM root list once. Returns the number of roots or < 0. */
JNIEXPORT jint JNICALL JFN(init)(JNIEnv *env, jclass cls, jbyteArray pem)
{
    jint ret;
    pthread_mutex_lock(&g_lock);
    if (g_roots_count == 0) {
        jsize n = (*env)->GetArrayLength(env, pem);
        unsigned char *buf = malloc((size_t) n + 1);
        int r;
        if (buf == NULL) { pthread_mutex_unlock(&g_lock); return RET_NO_MEMORY; }
        (*env)->GetByteArrayRegion(env, pem, 0, n, (jbyte *) buf);
        buf[n] = 0;
        r = (int) psa_crypto_init();
        if (r != PSA_SUCCESS) {
            free(buf);
            pthread_mutex_unlock(&g_lock);
            LOGW("psa_crypto_init failed: %d", r);
            return r < 0 ? r : -r;
        }
        mbedtls_x509_crt_init(&g_roots);
        r = mbedtls_x509_crt_parse(&g_roots, buf, (size_t) n + 1);
        free(buf);
        if (r < 0) {
            mbedtls_x509_crt_free(&g_roots);
            pthread_mutex_unlock(&g_lock);
            return r;
        }
        if (r > 0) LOGW("%d root certificates could not be parsed", r);
        {
            const mbedtls_x509_crt *p;
            for (p = &g_roots; p != NULL && p->raw.len > 0; p = p->next) g_roots_count++;
        }
    }
    ret = g_roots_count;
    pthread_mutex_unlock(&g_lock);
    return ret;
}

static void conn_free(conn *c)
{
    mbedtls_ssl_free(&c->ssl);
    mbedtls_ssl_config_free(&c->conf);
    mbedtls_ctr_drbg_free(&c->drbg);
    mbedtls_entropy_free(&c->entropy);
    free(c->in.buf);
    free(c->out.buf);
    free(c);
}

/* Creates a client connection for host. Returns a handle (> 0) or an error (< 0). */
JNIEXPORT jlong JNICALL JFN(open)(JNIEnv *env, jclass cls, jstring jhost, jint port)
{
    static const char pers[] = "lightning-xt550";
    const char *host;
    conn *c;
    int r;
    if (g_roots_count <= 0) return RET_NOT_READY;
    c = calloc(1, sizeof(conn));
    if (c == NULL) return RET_NO_MEMORY;
    mbedtls_ssl_init(&c->ssl);
    mbedtls_ssl_config_init(&c->conf);
    mbedtls_ctr_drbg_init(&c->drbg);
    mbedtls_entropy_init(&c->entropy);
    r = mbedtls_ctr_drbg_seed(&c->drbg, mbedtls_entropy_func, &c->entropy,
                              (const unsigned char *) pers, sizeof(pers) - 1);
    if (r == 0)
        r = mbedtls_ssl_config_defaults(&c->conf, MBEDTLS_SSL_IS_CLIENT,
                                        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (r == 0) {
        mbedtls_ssl_conf_authmode(&c->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&c->conf, &g_roots, NULL);
        mbedtls_ssl_conf_rng(&c->conf, mbedtls_ctr_drbg_random, &c->drbg);
        mbedtls_ssl_conf_min_tls_version(&c->conf, MBEDTLS_SSL_VERSION_TLS1_2);
#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_SSL_SESSION_TICKETS)
        mbedtls_ssl_conf_tls13_enable_signal_new_session_tickets(
            &c->conf, MBEDTLS_SSL_TLS1_3_SIGNAL_NEW_SESSION_TICKETS_ENABLED);
#endif
        r = mbedtls_ssl_setup(&c->ssl, &c->conf);
    }
    if (r == 0) {
        host = (*env)->GetStringUTFChars(env, jhost, NULL);
        if (host == NULL) {
            r = RET_NO_MEMORY;
        } else {
            r = mbedtls_ssl_set_hostname(&c->ssl, host); /* SNI + name check */
            snprintf(c->key, sizeof(c->key), "%s:%d", host, (int) port);
            (*env)->ReleaseStringUTFChars(env, jhost, host);
        }
    }
    if (r != 0) {
        conn_free(c);
        return r;
    }
    mbedtls_ssl_set_bio(&c->ssl, c, bio_send, bio_recv, NULL);
    {
        cache_entry *e;
        pthread_mutex_lock(&g_cache_lock);
        e = cache_find(c->key);
        if (e != NULL) {
            mbedtls_ssl_session sess;
            mbedtls_ssl_session_init(&sess);
            if (mbedtls_ssl_session_load(&sess, e->session, e->session_len) == 0
                && mbedtls_ssl_set_session(&c->ssl, &sess) == 0) {
                c->offered = 1;
                e->used = ++g_cache_clock;
            } else {
                cache_drop(e);
            }
            mbedtls_ssl_session_free(&sess);
        }
        pthread_mutex_unlock(&g_cache_lock);
    }
    return (jlong) (uintptr_t) c;
}

/* 0 = done, RET_WANT_READ = feed more network bytes, < 0 = error. */
JNIEXPORT jint JNICALL JFN(handshake)(JNIEnv *env, jclass cls, jlong p)
{
    conn *c = C(p);
    int r, spins = 0;
    do {
        r = mbedtls_ssl_handshake(&c->ssl);
    } while (r == MBEDTLS_ERR_SSL_WANT_READ && can_progress(c) && ++spins < 1000);
    if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) return RET_WANT_READ;
    if (r == MBEDTLS_ERR_SSL_CONN_EOF) return RET_EOF;
    if (r == 0 && mbedtls_ssl_get_version_number(&c->ssl) == MBEDTLS_SSL_VERSION_TLS1_2)
        cache_store(c);
    if (r != 0 && c->offered) {
        /* a stale cached session must not keep failing: forget it */
        cache_entry *e;
        pthread_mutex_lock(&g_cache_lock);
        e = cache_find(c->key);
        if (e != NULL) cache_drop(e);
        pthread_mutex_unlock(&g_cache_lock);
    }
    return r;
}

/* len < 0 marks the end of the TCP stream. */
JNIEXPORT jint JNICALL JFN(feed)(JNIEnv *env, jclass cls, jlong p, jbyteArray b, jint off, jint len)
{
    conn *c = C(p);
    jbyte *d;
    int r;
    if (len < 0) { c->eof = 1; return 0; }
    d = (*env)->GetByteArrayElements(env, b, NULL);
    if (d == NULL) return RET_NO_MEMORY;
    r = bb_append(&c->in, (const unsigned char *) d + off, (size_t) len);
    (*env)->ReleaseByteArrayElements(env, b, d, JNI_ABORT);
    return r == 0 ? 0 : RET_NO_MEMORY;
}

/* Bytes that must be sent to the server, or null. */
JNIEXPORT jbyteArray JNICALL JFN(takeOutput)(JNIEnv *env, jclass cls, jlong p)
{
    conn *c = C(p);
    size_t n = c->out.len - c->out.pos;
    jbyteArray a;
    if (n == 0) return NULL;
    a = (*env)->NewByteArray(env, (jsize) n);
    if (a == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, a, 0, (jsize) n, (const jbyte *) (c->out.buf + c->out.pos));
    c->out.pos = c->out.len = 0;
    return a;
}

/* > 0 bytes read, RET_EOF, RET_WANT_READ or an error (< 0). */
JNIEXPORT jint JNICALL JFN(read)(JNIEnv *env, jclass cls, jlong p, jbyteArray b, jint off, jint len)
{
    conn *c = C(p);
    unsigned char tmp[4096];
    int r, spins = 0;
    if (len > (jint) sizeof(tmp)) len = sizeof(tmp);
    for (;;) {
        r = mbedtls_ssl_read(&c->ssl, tmp, (size_t) len);
        if (r == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
            cache_store(c);
            continue;
        }
        if (r == MBEDTLS_ERR_SSL_WANT_READ && can_progress(c) && ++spins < 1000) continue;
        break;
    }
    if (r > 0) {
        (*env)->SetByteArrayRegion(env, b, off, r, (const jbyte *) tmp);
        return r;
    }
    if (r == 0 || r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || r == MBEDTLS_ERR_SSL_CONN_EOF) return RET_EOF;
    if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) return RET_WANT_READ;
    return r;
}

/* > 0 bytes accepted, RET_WANT_READ or an error (< 0). */
JNIEXPORT jint JNICALL JFN(write)(JNIEnv *env, jclass cls, jlong p, jbyteArray b, jint off, jint len)
{
    conn *c = C(p);
    jbyte *d = (*env)->GetByteArrayElements(env, b, NULL);
    int r;
    if (d == NULL) return RET_NO_MEMORY;
    r = mbedtls_ssl_write(&c->ssl, (const unsigned char *) d + off, (size_t) len);
    (*env)->ReleaseByteArrayElements(env, b, d, JNI_ABORT);
    if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) return RET_WANT_READ;
    return r;
}

/* DER certificates of the server (leaf first). For a resumed session these are
 * the ones verified by the full handshake that created it. */
JNIEXPORT jobjectArray JNICALL JFN(peerChain)(JNIEnv *env, jclass cls, jlong p)
{
    conn *c = C(p);
    jclass bytes = (*env)->FindClass(env, "[B");
    unsigned char *blob, *q;
    size_t len = 0, off;
    jsize n = 0, i = 0;
    jobjectArray out;
    blob = chain_blob(&c->ssl, &len);
    if (blob == NULL && c->offered) {
        cache_entry *e;
        pthread_mutex_lock(&g_cache_lock);
        e = cache_find(c->key);
        if (e != NULL && e->chain != NULL && (blob = malloc(e->chain_len)) != NULL) {
            memcpy(blob, e->chain, e->chain_len);
            len = e->chain_len;
        }
        pthread_mutex_unlock(&g_cache_lock);
    }
    for (off = 0; off + 4 <= len; n++)
        off += 4 + (((size_t) blob[off] << 24) | ((size_t) blob[off + 1] << 16)
                    | ((size_t) blob[off + 2] << 8) | blob[off + 3]);
    out = (*env)->NewObjectArray(env, n, bytes, NULL);
    for (off = 0; out != NULL && i < n; i++) {
        size_t l = ((size_t) blob[off] << 24) | ((size_t) blob[off + 1] << 16)
                   | ((size_t) blob[off + 2] << 8) | blob[off + 3];
        jbyteArray a;
        q = blob + off + 4;
        a = (*env)->NewByteArray(env, (jsize) l);
        if (a == NULL) { out = NULL; break; }
        (*env)->SetByteArrayRegion(env, a, 0, (jsize) l, (const jbyte *) q);
        (*env)->SetObjectArrayElement(env, out, i, a);
        (*env)->DeleteLocalRef(env, a);
        off += 4 + l;
    }
    free(blob);
    return out;
}

/* 1 if this connection resumed a cached session. */
JNIEXPORT jint JNICALL JFN(resumed)(JNIEnv *env, jclass cls, jlong p)
{
    conn *c = C(p);
    return c->offered && mbedtls_ssl_get_peer_cert(&c->ssl) == NULL;
}

JNIEXPORT jstring JNICALL JFN(info)(JNIEnv *env, jclass cls, jlong p)
{
    char s[160];
    snprintf(s, sizeof(s), "%s %s", mbedtls_ssl_get_version(&C(p)->ssl),
             mbedtls_ssl_get_ciphersuite(&C(p)->ssl));
    return (*env)->NewStringUTF(env, s);
}

/* Why the certificate was rejected, or null. */
JNIEXPORT jstring JNICALL JFN(verifyInfo)(JNIEnv *env, jclass cls, jlong p)
{
    char s[512];
    uint32_t flags = mbedtls_ssl_get_verify_result(&C(p)->ssl);
    if (flags == 0 || flags == (uint32_t) -1) return NULL;
    mbedtls_x509_crt_verify_info(s, sizeof(s), "", flags);
    return (*env)->NewStringUTF(env, s);
}

JNIEXPORT jstring JNICALL JFN(errorString)(JNIEnv *env, jclass cls, jint code)
{
    char s[200];
    switch (code) {
    case RET_EOF: return (*env)->NewStringUTF(env, "connection closed");
    case RET_NOT_READY: return (*env)->NewStringUTF(env, "root list not loaded");
    case RET_NO_MEMORY: return (*env)->NewStringUTF(env, "out of memory");
    }
    mbedtls_strerror(code, s, sizeof(s));
    return (*env)->NewStringUTF(env, s);
}

JNIEXPORT void JNICALL JFN(closeNotify)(JNIEnv *env, jclass cls, jlong p)
{
    mbedtls_ssl_close_notify(&C(p)->ssl);
}

JNIEXPORT void JNICALL JFN(free)(JNIEnv *env, jclass cls, jlong p)
{
    conn_free(C(p));
}
