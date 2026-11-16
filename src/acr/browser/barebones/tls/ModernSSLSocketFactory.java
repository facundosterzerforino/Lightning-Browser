package acr.browser.barebones.tls;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

import javax.net.ssl.SSLSocketFactory;

/** Hands out {@link ModernSSLSocket}s (mbedTLS) instead of Android 2.3's OpenSSL 1.0.0 ones. */
final class ModernSSLSocketFactory extends SSLSocketFactory {
	private static final String[] SUITES = { "TLS_MBEDTLS_DEFAULT" };

	@Override
	public Socket createSocket() throws IOException {
		return new ModernSSLSocket();
	}

	@Override
	public Socket createSocket(String host, int port) throws IOException {
		ModernSSLSocket s = new ModernSSLSocket();
		s.connect(new InetSocketAddress(host, port));
		return s;
	}

	@Override
	public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
			throws IOException {
		ModernSSLSocket s = new ModernSSLSocket();
		s.bind(new InetSocketAddress(localHost, localPort));
		s.connect(new InetSocketAddress(host, port));
		return s;
	}

	@Override
	public Socket createSocket(InetAddress host, int port) throws IOException {
		ModernSSLSocket s = new ModernSSLSocket();
		s.connect(new InetSocketAddress(host, port));
		return s;
	}

	@Override
	public Socket createSocket(InetAddress address, int port, InetAddress localAddress,
			int localPort) throws IOException {
		ModernSSLSocket s = new ModernSSLSocket();
		s.bind(new InetSocketAddress(localAddress, localPort));
		s.connect(new InetSocketAddress(address, port));
		return s;
	}

	@Override
	public Socket createSocket(Socket s, String host, int port, boolean autoClose)
			throws IOException {
		return new ModernSSLSocket(s, host, port, autoClose);
	}

	@Override
	public String[] getDefaultCipherSuites() {
		return SUITES.clone();
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return SUITES.clone();
	}
}
