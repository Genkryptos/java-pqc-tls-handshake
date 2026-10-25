import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * One-shot TCP proxy that counts the bytes of a TLS connection passing through it.
 * It doesn't decrypt anything: it only reads the 5-byte header of the first TLS record
 * in each direction. The client's first record is the ClientHello; the server's first
 * record is the ServerHello (or a HelloRetryRequest, or an alert if the handshake fails).
 *
 * Usage: java Proxy.java <listenPort> <targetHost> <targetPort>
 * Runs as a single source file on JDK 21+ (no build step).
 */
public class Proxy {

    public static void main(String[] args) throws Exception {
        int listenPort = Integer.parseInt(args[0]);
        String targetHost = args[1];
        int targetPort = Integer.parseInt(args[2]);

        try (ServerSocket listener = new ServerSocket(listenPort)) {
            listener.setSoTimeout(30_000);
            System.out.println("LISTENING on port " + listenPort + " -> " + targetHost + ":" + targetPort);
            try (Socket client = listener.accept(); Socket server = new Socket(targetHost, targetPort)) {
                client.setSoTimeout(15_000);
                server.setSoTimeout(15_000);
                Pump up = new Pump("client->server", client, server);
                Pump down = new Pump("server->client", server, client);
                up.start();
                down.start();
                up.join();
                down.join();
                System.out.println(up.report());
                System.out.println(down.report());
            }
        }
    }

    static final class Pump extends Thread {
        private final String label;
        private final Socket from;
        private final Socket to;
        private final byte[] header = new byte[5];
        private int headerBytes;
        private long total;

        Pump(String label, Socket from, Socket to) {
            this.label = label;
            this.from = from;
            this.to = to;
        }

        @Override
        public void run() {
            byte[] buffer = new byte[8192];
            try {
                InputStream in = from.getInputStream();
                OutputStream out = to.getOutputStream();
                int n;
                while ((n = in.read(buffer)) != -1) {
                    for (int i = 0; i < n && headerBytes < header.length; i++) {
                        header[headerBytes++] = buffer[i];
                    }
                    total += n;
                    out.write(buffer, 0, n);
                    out.flush();
                }
            } catch (IOException e) {
                // Connection reset or timeout: report whatever was counted so far.
            } finally {
                try {
                    to.shutdownOutput();
                } catch (IOException ignored) {
                    // Peer already closed.
                }
            }
        }

        String report() {
            if (headerBytes < header.length) {
                return label + ": first TLS record incomplete; total=" + total + " bytes";
            }
            int type = header[0] & 0xFF;
            int length = ((header[3] & 0xFF) << 8) | (header[4] & 0xFF);
            return label + ": first TLS record type=" + type + " (" + typeName(type) + ")"
                    + " length=" + length + " bytes (+5 byte record header); total=" + total + " bytes";
        }

        private static String typeName(int type) {
            switch (type) {
                case 20: return "change_cipher_spec";
                case 21: return "alert";
                case 22: return "handshake";
                case 23: return "application_data";
                default: return "unknown";
            }
        }
    }
}
