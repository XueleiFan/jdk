/*
 * Copyright (c) 2019, 2020, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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

package sun.security.ssl;

import sun.security.ssl.SSLExtension.ExtensionConsumer;
import sun.security.ssl.SSLExtension.SSLExtensionSpec;
import sun.security.ssl.SSLHandshake.HandshakeMessage;
import sun.security.ssl.SSLSessionImpl.ClientSession;
import sun.security.ssl.SSLSessionImpl.ServerSession;
import sun.security.ssl.SupportedGroupsExtension.SupportedGroups;
import static sun.security.ssl.SSLExtension.CH_SESSION_TICKET;
import static sun.security.ssl.SSLExtension.SH_SESSION_TICKET;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * The SessionTicket extension implementation for TLS 1.2 and prior versions.
 */
final class SessionTicketExtension {
    static final HandshakeProducer chNetworkProducer =
            new CHSessionTicketProducer();
    static final ExtensionConsumer chOnLoadConsumer =
            new CHSessionTicketConsumer();
    static final HandshakeProducer shNetworkProducer =
            new SHSessionTicketProducer();
    static final ExtensionConsumer shOnLoadConsumer =
            new SHSessionTicketConsumer();

    static final class SessionTicketSpec implements SSLExtensionSpec {
        // A nominal object that does not holding any real information.
        static final SessionTicketSpec NOMINAL = new SessionTicketSpec();

        private SessionTicketSpec() {
            // blank
        }
    }

    /**
     * Network data producer of a "session_ticket" extension in
     * the ClientHello handshake message.
     */
    private static final
    class CHSessionTicketProducer implements HandshakeProducer {
        // Prevent instantiation of this class.
        private CHSessionTicketProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                              HandshakeMessage message) throws IOException {
            // The producing happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            // Is it a supported and enabled extension?
            if (!chc.sslConfig.isAvailable(CH_SESSION_TICKET)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "Ignore unavailable session_ticket extension");
                }

                return null;
            }

            byte[] extData;
            // If resumption is not in progress, return an empty value
            if (!chc.isResumption || chc.resumingSession == null) {
                // Use empty session ticket extension for initial handshake.
                extData = new byte[0];
            } else if (chc.resumingSession.isValid() &&
                    !chc.resumingSession.protocolVersion.useTLS13PlusSpec()) {
                // Note: it could be an empty session ticket extension if
                // the cached session ticket is expired.
                NewSessionTicket.SessionTicket sessionTicket =
                    ((ClientSession)chc.resumingSession).getSessionTicket();
                if (sessionTicket != null) {
                    extData = sessionTicket.ticket;
                } else {
                    // cannot resume with session ticket, fallback to normal
                    // session resumption.
                    //    chc.isResumption = false;
                    //   chc.resumingSession = null;
                    //    extData = new byte[0];
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine(
                                "Fallback to session-id based resumption, " +
                                "ignore the extension: " +
                                CH_SESSION_TICKET.name);
                    }

                    return null;
                }
            } else {    // Unlikely, ignore the extension.
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "Not session resumption, ignore the extension: " +
                            CH_SESSION_TICKET.name);
                }
                return null;
            }

            // Update the context.
            chc.handshakeExtensions.put(
                    CH_SESSION_TICKET, SessionTicketSpec.NOMINAL);

            return extData;
        }
    }

    /**
     * Network data consumer of a "session_ticket" extension in
     * the ClientHello handshake message.
     */
    private static final
    class CHSessionTicketConsumer implements ExtensionConsumer {
        // Prevent instantiation of this class.
        private CHSessionTicketConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
            HandshakeMessage message, ByteBuffer buffer) throws IOException {

            // The consuming happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            // Skip if extension is not provided
            if (!shc.sslConfig.isAvailable(SH_SESSION_TICKET)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable extension: " +
                            SH_SESSION_TICKET.name);
                }

                return;     // ignore the extension
            }

            // Impact on session resumption.
            if (!buffer.hasRemaining()) {
                // Empty session_ticket extension, not for session resumption.
                shc.isResumption = false;
            } else if (shc.isResumption) {
                // Here is a non-empty session ticket.
                byte[] decodedTicket =
                        shc.sslContext.getTicketManager().decodeTicket(buffer);
                if (decodedTicket == null || decodedTicket.length == 0) {
                    // Ignore, the session ticket cannot be used.
                    shc.isResumption = false;
                } else {
                    shc.resumingSession =
                            ServerSession.decodeT12StatelessTicket(
                                    shc, decodedTicket);
                    if (shc.resumingSession == null) {
                        // Ignore, the session ticket cannot be used.
                        shc.isResumption = false;
                    }
                }
            } else {    // Otherwise, this is not session resumption.
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "Not session resumption, ignore the extension: " +
                            CH_SESSION_TICKET.name);
                }
            }

            shc.handshakeExtensions.put(
                    CH_SESSION_TICKET, SessionTicketSpec.NOMINAL);
        }
    }

    /**
     * Network data producer of a "session_ticket" extension in
     * the ServerHello handshake message.
     */
    private static final class SHSessionTicketProducer
            extends SupportedGroups implements HandshakeProducer {
        // Prevent instantiation of this class.
        private SHSessionTicketProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                              HandshakeMessage message) {
            // The producing happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;
            ServerHello.ServerHelloMessage serverHello =
                    (ServerHello.ServerHelloMessage)message;

            // In response to "session_ticket" extension request only.
            if (!shc.handshakeExtensions.containsKey(
                    SSLExtension.CH_SESSION_TICKET)) {
                return null;        // no need to response
            }

            if (!shc.handshakeSession.worthyOfCache()) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "Unable to use session_ticket handshake message");
                }

                return null;
            }

            // Update the context.
            if (!shc.isResumption) {
                // If a server is planning on issuing a session ticket to a
                // client that does not present one, it SHOULD include an
                // empty Session ID in the ServerHello. [RFC 5077 3.4]
                //
                // Or if the server does not accept the session ticket, an
                // empty Session ID could be used in the ServerHello.
                serverHello.sessionId = new SessionId(new byte[0]);
            }
            shc.handshakeExtensions.put(
                    SH_SESSION_TICKET, SessionTicketSpec.NOMINAL);

            // Empty session ticket extension is used in server side.
            return new byte[0];
        }
    }

    /**
     * Network data consumer of a "session_ticket" extension in
     * the ServerHello handshake message.
     */
    private static final class SHSessionTicketConsumer
            implements ExtensionConsumer {
        // Prevent instantiation of this class.
        private SHSessionTicketConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
            HandshakeMessage message, ByteBuffer buffer) throws IOException {

            ClientHandshakeContext chc = (ClientHandshakeContext) context;

            if (!chc.handshakeExtensions.containsKey(
                    SSLExtension.CH_SESSION_TICKET)) {
                // No session_ticket requested in client side.
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE,
                    "Unexpected session_ticket extension in ServerHello");
            }

            if (buffer.hasRemaining()) {
                // Empty session ticket extension is always used in server side.
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE,
                    "Non-empty session_ticket extension");
            }

            // Update the context.  Ready to accept NewSessionTicket handshake
            // message.
            chc.handshakeExtensions.put(
                    SH_SESSION_TICKET, SessionTicketSpec.NOMINAL);
        }
    }
}

