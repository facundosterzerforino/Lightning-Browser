package acr.browser.barebones.tls;

/** JNI bridge to jni/moderntls.c (mbedTLS). One handle per TLS connection. */
final class NativeTls {
	static final int EOF = -0x10001;
	static final int WANT_READ = -0x10002;

	private NativeTls() {
	}

	static native int init(byte[] pem);

	static native long open(String host, int port);

	static native int handshake(long c);

	static native int feed(long c, byte[] b, int off, int len);

	static native byte[] takeOutput(long c);

	static native int read(long c, byte[] b, int off, int len);

	static native int write(long c, byte[] b, int off, int len);

	static native byte[][] peerChain(long c);

	static native int resumed(long c);

	static native String info(long c);

	static native String verifyInfo(long c);

	static native String errorString(int code);

	static native void closeNotify(long c);

	static native void free(long c);
}
