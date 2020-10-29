/*
 * Copyright (c) 2020, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

//
// SunJSSE does not support dynamic system properties, no way to re-use
// system properties in samevm/agentvm mode.
//

/*
 * @test
 * @bug 8245576
 * @summary Distributed TLS sessions implementation
 * @modules jdk.crypto.ec
 * @library /javax/net/ssl/templates
 * @run main/othervm DistributedSessions
 */
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.concurrent.*;

public class DistributedSessions implements SSLContextTemplate {
    private final CountDownLatch connACondition = new CountDownLatch(1);
    private final CountDownLatch connBCondition = new CountDownLatch(1);
    private final ExecutorService executor = Executors.newCachedThreadPool();

    public static void main(String[] args) throws Exception {
        (new DistributedSessions()).runTest();
    }

    private void runTest() throws Exception {
        try (
            ServerSocket serverNodeA =
                    createServerNode(connACondition);
            ServerSocket serverNodeB =
                    createServerNode(connBCondition);
            ServerSocket proxyServer =
                    createProxyServer(serverNodeA, serverNodeB)) {

            // Note: please use the same SSLContext object for clients.
            SSLContext context = createClientSSLContext();
            SSLSocketFactory socketFactory = context.getSocketFactory();

            // Full handshake is expected.
            byte[] connASessionId;
            try (SSLSocket socket = (SSLSocket)socketFactory.createSocket()) {
                socket.connect(proxyServer.getLocalSocketAddress(), 15000);

                // Signal the server, the client is ready to communicate.
                connACondition.countDown();

                // Run the application in client side.
                runClientApp(socket);

                connASessionId = socket.getSession().getId();
            }

            // Abbreviated handshake is expected.
            byte[] connBSessionId;
            try (SSLSocket socket = (SSLSocket)socketFactory.createSocket()) {
                socket.connect(proxyServer.getLocalSocketAddress(), 15000);

                // Signal the server, the client is ready to communicate.
                connBCondition.countDown();

                // Run the application in client side.
                runClientApp(socket);

                connBSessionId = socket.getSession().getId();
            }

            if (!Arrays.equals(connASessionId, connBSessionId)) {
                throw new Exception("Distributed sessions resumption failed");
            }
        } finally {
            executor.shutdownNow();
        }
    }

    private ServerSocket createServerNode(
            CountDownLatch clientCondition) throws Exception {
        // Note: please use different SSLContext objects for different servers.
        SSLContext context = createServerSSLContext();
        ServerSocket serverSocket =
                context.getServerSocketFactory().createServerSocket(0);

        // Try to accept a connection in 30 seconds.
        serverSocket.setSoTimeout(30000);
        executor.submit(() -> acceptConnection(serverSocket, clientCondition));

        return serverSocket;
    }

    private static void acceptConnection(
            ServerSocket serverSocket, CountDownLatch clientCondition) {
        // Only need one connection.
        try (Socket socket = serverSocket.accept()) {
            // Is it the expected client connection?
            //
            // Naughty test cases or third party routines may try to
            // connection to this server port unintentionally.  In
            // order to mitigate the impact of unexpected client
            // connections and avoid intermittent failure, it should
            // be checked that the accepted connection is really linked
            // to the expected client.
            boolean clientIsReady =
                    clientCondition.await(30L, TimeUnit.SECONDS);

            if (clientIsReady) {
                // Run the application in server side.
                runServerApp(socket);
            } else {    // Otherwise, ignore
                // We don't actually care about plain socket connections
                // for TLS communication testing generally.  Just ignore
                // the test if the accepted connection is not linked to
                // the expected client or the client connection timeout
                // in 30 seconds.
                System.err.println(
                        "The client is not the expected one or timeout. " +
                                "Ignore in server side.");
            }
        } catch (IOException | InterruptedException ioe) {
            System.err.println("SSL server failed: " + ioe);
            ioe.printStackTrace(System.err);
        }
    }

    private ServerSocket createProxyServer(
            ServerSocket serverNodeA,
            ServerSocket serverNodeB) throws Exception {
        ServerSocket proxyServerSocket = new ServerSocket(0);

        // Try to accept a connection in 30 seconds.
        proxyServerSocket.setSoTimeout(30000);
        executor.submit(() -> {
            // full handshake connection
            acceptProxy(executor,
                    proxyServerSocket, serverNodeA, connACondition);

            // resumption connection
            acceptProxy(executor,
                    proxyServerSocket, serverNodeB, connBCondition);
        });

        return proxyServerSocket;
    }

    private static void acceptProxy(
            ExecutorService executorService,
            ServerSocket proxyServerSocket,
            ServerSocket targetSocket,
            CountDownLatch clientCondition) {
        // Only need one connection.
        try {
            // Note: Please don't use try-with-resources for the socket, as it
            // will be used in the proxy thread in a future mode.
            Socket socket = proxyServerSocket.accept();

            // Is it the expected client connection?
            //
            // Naughty test cases or third party routines may try to
            // connection to this server port unintentionally.  In
            // order to mitigate the impact of unexpected client
            // connections and avoid intermittent failure, it should
            // be checked that the accepted connection is really linked
            // to the expected client.
            boolean clientIsReady =
                    clientCondition.await(30L, TimeUnit.SECONDS);

            if (clientIsReady) {
                // Run the application in server side.
                executorService.submit(new ProxyConnection(
                        executorService, targetSocket, socket));
            } else {    // Otherwise, ignore
                // We don't actually care about plain socket connections
                // for TLS communication testing generally.  Just ignore
                // the test if the accepted connection is not linked to
                // the expected client or the client connection timeout
                // in 30 seconds.
                System.err.println(
                        "The client is not the expected one or timeout. " +
                                "Ignore in server side.");
            }
        } catch (IOException | InterruptedException ioe) {
            System.err.println("SSL server failed: " + ioe);
            ioe.printStackTrace(System.err);
        }
    }

    private static void runServerApp(Socket socket) throws IOException {
        InputStream sslIS = socket.getInputStream();
        OutputStream sslOS = socket.getOutputStream();

        sslIS.read();
        sslOS.write(85);
        sslOS.flush();
    }

    protected void runClientApp(Socket socket) throws Exception {
        InputStream sslIS = socket.getInputStream();
        OutputStream sslOS = socket.getOutputStream();

        sslOS.write(280);
        sslOS.flush();
        sslIS.read();
    }

    private static class ProxyConnection implements Runnable {
        private final Socket clientSocket;
        private final ExecutorService executorService;
        private final ServerSocket targetSocket;

        ProxyConnection(ExecutorService executorService,
                        ServerSocket targetSocket, Socket clientSocket) {
            this.clientSocket = clientSocket;
            this.executorService = executorService;
            this.targetSocket = targetSocket;
        }

        @Override
        public void run() {
            try (InputStream clientIs = clientSocket.getInputStream();
                 OutputStream clientOs = clientSocket.getOutputStream()) {
                try (Socket serviceSocket = new Socket(
                        targetSocket.getInetAddress(),
                        targetSocket.getLocalPort())) {
                    final InputStream serverIs =
                            serviceSocket.getInputStream();
                    final OutputStream serverOs =
                            serviceSocket.getOutputStream();
                    final Future<?> future = executorService.submit(
                            () -> pipe(clientIs, serverOs));
                    pipe(serverIs, clientOs);
                    future.get();
                } catch (InterruptedException | ExecutionException ire) {
                    clientSocket.close();
                    System.err.println("SSL server failed: " + ire);
                    ire.printStackTrace(System.err);
                }
            } catch (IOException ioe) {
                try {
                    clientSocket.close();
                } catch (IOException e) {
                    // ignore
                }
                System.err.println("SSL server failed: " + ioe);
                ioe.printStackTrace(System.err);
            }
        }

        private void pipe(InputStream is, OutputStream os) {
            byte[] bug = new byte[4096];
            int len;
            try {
                while ((len = is.read(bug)) >= 0) {
                    os.write(bug, 0, len);
                }
            } catch (IOException e) {
                try {
                    is.close();
                    os.close();
                    clientSocket.close();
                } catch (IOException ioe) {
                    System.err.println("SSL server failed: " + ioe);
                    ioe.printStackTrace(System.err);
                }
            }
        }
    }
}
