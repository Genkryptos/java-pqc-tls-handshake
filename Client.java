import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;

/**
 * TLS 1.3 client for the post-quantum hybrid key exchange experiment.
 * Connects once, prints what was negotiated, then exits.
 *
 * Usage:
 *   java Client.java <host> <port> <truststore.p12> <password>   local Server.java: also exchanges one line
 *   java Client.java <host> <port>                               public server: JDK default trust store,
 *                                                                hostname verified, handshake only
 * Runs as a single source file on JDK 21+ (no build step).
 */
public class Client {

    public static void main(String[] args) throws Exception {
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        boolean local = args.length >= 4;

        SSLContext context = SSLContext.getInstance("TLS");
        if (local) {
            char[] password = args[3].toCharArray();
            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            try (InputStream in = new FileInputStream(args[2])) {
                trustStore.load(in, password);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            context.init(null, tmf.getTrustManagers(), null);
        } else {
            context.init(null, null, null);
        }

        try (SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket(host, port)) {
            socket.setEnabledProtocols(new String[] {"TLSv1.3"});
            socket.setSoTimeout(10_000);
            if (!local) {
                SSLParameters params = socket.getSSLParameters();
                params.setEndpointIdentificationAlgorithm("HTTPS");
                socket.setSSLParameters(params);
            }

            System.out.println("CLIENT java.version: " + System.getProperty("java.version"));
            System.out.println("CLIENT jdk.tls.namedGroups: " + System.getProperty("jdk.tls.namedGroups", "(not set)"));
            System.out.println("CLIENT enabled named groups: " + namedGroups(socket.getSSLParameters()));

            try {
                socket.startHandshake();
            } catch (Exception e) {
                System.out.println("HANDSHAKE FAILED: " + e);
                System.exit(1);
            }
            SSLSession session = socket.getSession();
            System.out.println("HANDSHAKE OK protocol=" + session.getProtocol()
                    + " cipherSuite=" + session.getCipherSuite());
            if (!local) {
                return;
            }

            PrintWriter writer = new PrintWriter(socket.getOutputStream(), true, StandardCharsets.UTF_8);
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            writer.println("hello from client on Java " + System.getProperty("java.version"));
            System.out.println("CLIENT received: " + reader.readLine());
        }
    }

    static String namedGroups(SSLParameters params) {
        String[] groups = params.getNamedGroups();
        return groups == null ? "(null: provider default)" : Arrays.toString(groups);
    }
}
