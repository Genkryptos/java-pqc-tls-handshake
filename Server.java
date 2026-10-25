import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;

/**
 * One-shot TLS 1.3 server for the post-quantum hybrid key exchange experiment.
 * Accepts a single connection, prints what was negotiated, then exits.
 *
 * Usage: java Server.java <port> <keystore.p12> <password>
 * Runs as a single source file on JDK 21+ (no build step).
 */
public class Server {

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(args[0]);
        char[] password = args[2].toCharArray();

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(args[1])) {
            keyStore.load(in, password);
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, password);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), null, null);

        try (SSLServerSocket server = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(port)) {
            server.setEnabledProtocols(new String[] {"TLSv1.3"});
            server.setSoTimeout(30_000);

            System.out.println("SERVER java.version: " + System.getProperty("java.version"));
            System.out.println("SERVER jdk.tls.namedGroups: " + System.getProperty("jdk.tls.namedGroups", "(not set)"));
            System.out.println("SERVER enabled named groups: " + namedGroups(server.getSSLParameters()));
            System.out.println("LISTENING on port " + port);

            try (SSLSocket socket = (SSLSocket) server.accept()) {
                socket.setSoTimeout(10_000);
                socket.startHandshake();
                SSLSession session = socket.getSession();
                System.out.println("HANDSHAKE OK protocol=" + session.getProtocol()
                        + " cipherSuite=" + session.getCipherSuite());

                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
                PrintWriter writer = new PrintWriter(socket.getOutputStream(), true, StandardCharsets.UTF_8);
                System.out.println("SERVER received: " + reader.readLine());
                writer.println("hello from server on Java " + System.getProperty("java.version"));
            } catch (Exception e) {
                System.out.println("HANDSHAKE FAILED: " + e);
                System.exit(1);
            }
        }
    }

    static String namedGroups(SSLParameters params) {
        String[] groups = params.getNamedGroups();
        return groups == null ? "(null: provider default)" : Arrays.toString(groups);
    }
}
