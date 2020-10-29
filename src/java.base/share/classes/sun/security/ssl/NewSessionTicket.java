/*
 * Copyright (c) 2018, 2020, Oracle and/or its affiliates. All rights reserved.
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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Locale;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import sun.security.ssl.SSLHandshake.HandshakeMessage;
import sun.security.ssl.SSLSessionImpl.ServerSession;
import sun.security.util.HexDumpEncoder;

import static sun.security.ssl.SSLHandshake.NEW_SESSION_TICKET;

/**
 * Pack of the NewSessionTicket handshake message.
 */
final class NewSessionTicket {
    static final int MAX_TICKET_LIFETIME = 604800;  // seconds, 7 days
    static final SSLConsumer t13HandshakeConsumer =
        new T13NewSessionTicketConsumer();
    static final SSLConsumer t12HandshakeConsumer =
        new T12NewSessionTicketConsumer();
    static final SSLProducer t13HandshakeProducer =
        new T13NewSessionTicketProducer();
    static final HandshakeProducer t12HandshakeProducer =
        new T12NewSessionTicketProducer();


    /**
     * NewSessionTicket for TLS 1.2 and below (RFC 5077).
     *
     * handshake message:
     *       struct {
     *           uint32 ticket_lifetime_hint;
     *           opaque ticket<0..2^16-1>;
     *       } NewSessionTicket;
     */
    // Note: the ticket could be cached in client side.
    static class SessionTicket {
        // Milliseconds between the expire time and midnight,
        // January 1, 1970 UTC.
        final long expires;

        // Milliseconds since midnight January 1, 1970 UTC.
        final long creationTime;

        // the session ticket
        final byte[] ticket;

        // Note: the ticket parameter is not cloned for performance,
        // the caller MUST not update the ticket byte array after
        // the call to this method.
        SessionTicket(int lifetimeInSeconds, byte[] ticket) {
            this.creationTime = System.currentTimeMillis();
            this.expires = creationTime + lifetimeInSeconds * 1000;
            this.ticket = ticket;
        }
    }

    static final class T12NewSessionTicketMessage extends HandshakeMessage {
        SessionTicket sessionTicket;

        T12NewSessionTicketMessage(HandshakeContext hc,
                                   int ticketLifetimeHint, byte[] ticket) {
            super(hc.conContext);
            sessionTicket = new SessionTicket(ticketLifetimeHint, ticket);
        }

        T12NewSessionTicketMessage(HandshakeContext hc,
                ByteBuffer m) throws IOException {
            super(hc.conContext);

            if (m.remaining() < 6) {
                throw hc.conContext.fatal(Alert.DECODE_ERROR,
                    "Invalid NewSessionTicket message: insufficient data");
            }

            sessionTicket = new SessionTicket(
                    Record.getInt32(m), Record.getBytes16(m));
        }

        @Override
        public SSLHandshake handshakeType() {
            return NEW_SESSION_TICKET;
        }

        @Override
        public int messageLength() {
            return 4 +                  // ticketLifetime
                   2 + sessionTicket.ticket.length;   // len of ticket + ticket
        }

        @Override
        public void send(HandshakeOutStream hos) throws IOException {
            hos.putInt32((int)(sessionTicket.expires -
                    sessionTicket.creationTime) / 1000);
            hos.putBytes16(sessionTicket.ticket);
        }

        @Override
        public String toString() {
            MessageFormat messageFormat = new MessageFormat(
            "\"NewSessionTicket\": '{'\n" +
                    "  \"ticket_lifetime_hint\" : \"{0}\",\n" +
                    "  \"ticket\"               : '{'\n" +
                    "{1}\n" +
                    "  '}'" +
                    "'}'",
                Locale.ENGLISH);

            HexDumpEncoder hexEncoder = new HexDumpEncoder();
            Object[] messageFields = {
                    (sessionTicket.expires -
                            sessionTicket.creationTime) / 1000,
                    Utilities.indent(
                            hexEncoder.encode(sessionTicket.ticket), "    "),
            };

            return messageFormat.format(messageFields);
        }
    }

    /**
     * NewSessionTicket defined by the TLS 1.3
     *
     * post-handshake message:
     *       struct {
     *           uint32 ticket_lifetime;
     *           uint32 ticket_age_add;
     *           opaque ticket_nonce<0..255>;
     *           opaque ticket<1..2^16-1>;
     *           Extension extensions<0..2^16-2>;
     *       } NewSessionTicket;
     */
    // Note: the ticket could be cached in client side.
    static class T13SessionTicket extends SessionTicket {
        final int ticketAgeAdd;
        final SecretKey preSharedKey;

        private T13SessionTicket(int lifetimeInSeconds,
                                 int ticketAgeAdd,
                                 byte[] ticket,
                                 SecretKey preSharedKey) {
            super(lifetimeInSeconds, ticket);
            this.ticketAgeAdd = ticketAgeAdd;
            this.preSharedKey = preSharedKey;
        }
    }

    static final class T13NewSessionTicketMessage extends HandshakeMessage {
        final T13SessionTicket sessionTicket;
        final byte[] ticketNonce;
        final SSLExtensions extensions;

        T13NewSessionTicketMessage(TransportContext tc,
                int ticketLifetime, int ticketAgeAdd,
                byte[] ticketNonce, byte[] ticket,
                SecretKey preSharedKey) {
            super(tc);

            this.ticketNonce = ticketNonce;
            this.sessionTicket = new T13SessionTicket(
                    ticketLifetime, ticketAgeAdd, ticket, preSharedKey);
            this.extensions = new SSLExtensions(this);
        }

        T13NewSessionTicketMessage(TransportContext tc,
                ByteBuffer m) throws IOException {
            super(tc);

            if (m.remaining() < 14) {
                throw tc.fatal(Alert.DECODE_ERROR,
                    "Invalid NewSessionTicket message: insufficient data");
            }

            int ticketLifetime = Record.getInt32(m);
            int ticketAgeAdd = Record.getInt32(m);
            this.ticketNonce = Record.getBytes8(m);

            if (m.remaining() < 5) {
                throw tc.fatal(Alert.DECODE_ERROR,
                "Invalid NewSessionTicket message: insufficient ticket" +
                        " data");
            }

            byte[] ticket = Record.getBytes16(m);
            if (ticket.length == 0) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                        "No ticket in the NewSessionTicket handshake message");
                }
            }

            if (m.remaining() < 2) {
                throw tc.fatal(Alert.DECODE_ERROR,
                    "Invalid NewSessionTicket message: extra data");
            }

            SSLExtension[] enabledExtensions =
                    tc.sslConfig.getEnabledExtensions(
                            NEW_SESSION_TICKET);
            this.extensions = new SSLExtensions(this, m, enabledExtensions);

            // Derive the pre-shared key.
            SecretKey secretKey;
            try {
                secretKey = derivePreSharedKey(tc, ticketNonce);
            } catch (IOException e) {
                throw tc.fatal(Alert.ILLEGAL_PARAMETER,
                        "Unable to derive the pre-shared secret key");
            }
            this.sessionTicket = new T13SessionTicket(
                    ticketLifetime, ticketAgeAdd,
                    ticket, secretKey);
        }

        @Override
        public SSLHandshake handshakeType() {
            return NEW_SESSION_TICKET;
        }

        @Override
        public int messageLength() {
            int extLen = extensions.length();
            if (extLen == 0) {
                extLen = 2;     // empty extensions
            }

            return 4 +                          // ticketLifetime
                   4 +                          // ticketAgeAdd
                   1 + ticketNonce.length +   // nonce
                   2 + sessionTicket.ticket.length +        // ticket
                   extLen;
        }

        @Override
        public void send(HandshakeOutStream hos) throws IOException {
            hos.putInt32((int)(sessionTicket.expires -
                    sessionTicket.creationTime) / 1000);
            hos.putInt32(sessionTicket.ticketAgeAdd);
            hos.putBytes8(ticketNonce);
            hos.putBytes16(sessionTicket.ticket);

            // Is it an empty extensions?
            if (extensions.length() == 0) {
                hos.putInt16(0);
            } else {
                extensions.send(hos);
            }
        }

        @Override
        public String toString() {
            MessageFormat messageFormat = new MessageFormat(
                "\"NewSessionTicket\": '{'\n" +
                "  \"ticket_lifetime\" : \"{0}\",\n" +
                "  \"ticket_age_add\"  : \"{1}\",\n" +
                "  \"ticket_nonce\"    : \"{2}\",\n" +
                "  \"ticket\"          : '{'\n" +
                "{3}\n" +
                "  '}'" +
                "  \"extensions\"      : [\n" +
                "{4}\n" +
                "  ]\n" +
                "'}'",
                Locale.ENGLISH);

            HexDumpEncoder hexEncoder = new HexDumpEncoder();
            Object[] messageFields = {
                (int)(sessionTicket.expires -
                            sessionTicket.creationTime) / 1000,
                "<omitted>",    // ticketAgeAdd should not be logged
                Utilities.toHexString(ticketNonce),
                Utilities.indent(
                        hexEncoder.encode(sessionTicket.ticket), "    "),
                Utilities.indent(extensions.toString(), "    ")
            };

            return messageFormat.format(messageFields);
        }
    }

    /**
     * The "NewSessionTicket" handshake message producer for for TLS 1.2 and
     * prior versions (RFC 5077).
     */
    private static final class T12NewSessionTicketProducer
            implements HandshakeProducer {

        // Prevent instantiation of this class.
        private T12NewSessionTicketProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The producing happens in server handshake context only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            // Is this session resumable?
            if (!shc.handshakeExtensions.containsKey(
                            SSLExtension.SH_SESSION_TICKET)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                        "Ignore inapplicable NewSessionTicket handshake message");
                }

                return null;
            }

            byte[] ticket;
            ServerSession serverSession = (ServerSession)shc.handshakeSession;
            byte[] encodedSession = serverSession.encodeT12StatelessTicket();
            if (encodedSession != null && encodedSession.length != 0) {
                ticket = shc.sslContext.getTicketManager()
                        .encodeTicket(encodedSession);
                if (ticket == null) {       // unlikely, but just in case.
                    ticket = new byte[0];
                }
            } else {                        // unlikely, but just in case.
                ticket = new byte[0];
            }

            int sessionTimeoutSeconds =
                    shc.sslContext.serverCache.getSessionTimeout();
            int ticketLifetime =
                    Math.min(sessionTimeoutSeconds, MAX_TICKET_LIFETIME);
            HandshakeMessage hm = new T12NewSessionTicketMessage(shc,
                    ticketLifetime, ticket);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                        "Produced NewSessionTicket handshake message", hm);
            }

            // Output the handshake message.
            hm.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();

            // Update the context
            shc.hasSessionTicket = true;

            // The message has been delivered.
            return null;
        }
    }

    private static final
    class T12NewSessionTicketConsumer implements SSLConsumer {
        // Prevent instantiation of this class.
        private T12NewSessionTicketConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                            ByteBuffer message) throws IOException {
            // The consuming happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;
            chc.handshakeConsumers.remove(NEW_SESSION_TICKET.id);

            if (!chc.handshakeExtensions.containsKey(
                    SSLExtension.CH_SESSION_TICKET)) {
                // No session_ticket requested in client side.
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE,
                        "Unrequested NewSessionTicket handshake message");
            }

            if (!chc.handshakeExtensions.containsKey(
                            SSLExtension.SH_SESSION_TICKET)) {
                // No session_ticket presented in ServerHello.
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE,
                        "Unexpected NewSessionTicket handshake message");
            }

            T12NewSessionTicketMessage nstm =
                    new T12NewSessionTicketMessage(chc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming NewSessionTicket\n" + nstm);
            }

            if (nstm.sessionTicket.ticket.length == 0) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("NewSessionTicket.ticket was empty");
                }

                // Per RFC 5077, it's fine to have an empty ticket, but it does
                // not make sense to cache the ticket in client.
                return;
            }

            // Add the ticket to the session.
            ((SSLSessionImpl.ClientSession)chc.handshakeSession)
                    .putSessionTicket(nstm.sessionTicket);

            // Update the context
            // Note: The client does not use this field yet.
            // chc.hasSessionTicket = true;
        }
    }

    private static final
    class T13NewSessionTicketProducer implements SSLProducer {
        // Prevent instantiation of this class.
        private T13NewSessionTicketProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context) throws IOException {
            TransportContext tc = (TransportContext) context;

            // See note on TransportContext.needHandshakeFinishedStatus.
            //
            // Set to need handshake finished status.  Reset it later if a
            // session ticket get delivered.
            if (tc.hasDelegatedFinished) {
                // Reset, as the delegated finished case will be handled later.
                tc.hasDelegatedFinished = false;
                tc.needHandshakeFinishedStatus = true;
            }

            if (!tc.conSession.worthyOfCache()) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "No NewSessionTicket produced: session is not resumable");
                }

                return null;
            }

            // Generate the handshake message
            HandshakeMessage hm = null;
            if (tc.conSession.isStatelessable()) {
                hm = produceStatelessTicket(tc);
            }

            if (hm == null) {
                hm = produceStatefulTicket(tc);
            }

            // Output the handshake message.
            HandshakeOutStream hos = new HandshakeOutStream(tc.outputRecord);
            hm.write(hos);
            hos.flush();

            // See note on TransportContext.needHandshakeFinishedStatus.
            //
            // Reset the needHandshakeFinishedStatus flag.  The delivery
            // of this post-handshake message will indicate the FINISHED
            // handshake status.  It is not needed to have a follow-on
            // SSLEngine.wrap() any longer.
            if (tc.needHandshakeFinishedStatus) {
                tc.needHandshakeFinishedStatus = false;
            }

            // The message has been delivered.
            return null;
        }

        private static HandshakeMessage produceStatelessTicket(
                TransportContext tc) throws IOException {

            // Generate the ticket nonce.
            SecureRandom secureRandom = tc.sslContext.getSecureRandom();
            byte[] ticketNonce = new byte[8];
            secureRandom.nextBytes(ticketNonce);

            // Calculate the pre-shared key.
            SecretKey preSharedSecret = derivePreSharedKey(tc, ticketNonce);

            // Calculate the session ticket.
            ServerSession serverSession = (ServerSession) tc.conSession;
            byte[] encodedSession =
                    serverSession.encodeT13StatelessTicket(preSharedSecret);
            if (encodedSession == null || encodedSession.length == 0) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "Unable produce stateless NewSessionTicket: " +
                                    "cannot encode session data");
                }

                return null;
            }

            byte[] ticket = tc.sslContext.getTicketManager()
                    .encodeTicket(encodedSession);
            if (ticket == null || ticket.length == 0) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "Unable produce stateless NewSessionTicket: " +
                                    "cannot protect session data");
                }

                return null;
            }

            HandshakeMessage hm = new T13NewSessionTicketMessage(tc,
                    tc.sslContext.serverCache.getSessionTimeout(),
                    secureRandom.nextInt(),
                    ticketNonce,
                    ticket,
                    preSharedSecret);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                        "Produced stateless NewSessionTicket message", hm);
            }

            return hm;
        }

        private static HandshakeMessage produceStatefulTicket(
                TransportContext tc) throws IOException {
            ServerSession serverSession = (ServerSession) tc.conSession;
            long ticketId = tc.sslContext.getSecureRandom().nextLong();
            byte[] ticketNonce = Utilities.toByteArray(ticketId);

            // ticket = ticketNonce | sessionId
            byte[] sessionId = serverSession.getSessionId().getId();
            byte[] ticket = Arrays.copyOf(ticketNonce,
                    ticketNonce.length + sessionId.length);
            System.arraycopy(sessionId, 0,
                    ticket, ticketNonce.length, sessionId.length);

            int ticketAgeAdd = tc.sslContext.getSecureRandom().nextInt();
            int ticketLifetime =
                    tc.sslContext.serverCache.getSessionTimeout();

            T13NewSessionTicketMessage hm = new T13NewSessionTicketMessage(tc,
                    ticketLifetime,
                    ticketAgeAdd,
                    ticketNonce,
                    ticket,
                    derivePreSharedKey(tc, ticketNonce));
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                        "Produced stateful NewSessionTicket message", hm);
            }

            serverSession.putStatefulSessionTicket(ticketId, hm.sessionTicket);

            return hm;
        }
    }

    private static final
    class T13NewSessionTicketConsumer implements SSLConsumer {
        // Prevent instantiation of this class.
        private T13NewSessionTicketConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                ByteBuffer message) throws IOException {

            // Note: Although the resumption master secret depends on the
            // client's second flight, servers which do not request client
            // authentication MAY compute the remainder of the transcript
            // independently and then send a NewSessionTicket immediately
            // upon sending its Finished rather than waiting for the client
            // Finished.
            //
            // The consuming happens in client side only and is received after
            // the server's Finished message.
            TransportContext tc = (TransportContext)context;

            // Note: the current "psk_key_exchange_modes" extension
            // implementation use the "psk_dhe_ke" mode only.  Otherwise, it
            // is needed to check the requested pre-shared key exchange mode
            // here.
            if (!tc.sslConfig.isAvailable(
                    SSLExtension.PSK_KEY_EXCHANGE_MODES)) {
                // No session_ticket requested in client side.
                throw tc.fatal(Alert.UNEXPECTED_MESSAGE,
                        "Unexpected NewSessionTicket handshake message");
            }

            if (!tc.conSession.worthyOfCache()) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                        "Ignore NewSessionTicket message: the session is not rejoinable: " + tc.conSession);
                }

                return;
            }

            T13NewSessionTicketMessage nstm =
                    new T13NewSessionTicketMessage(tc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                        "Consuming NewSessionTicket message", nstm);
            }

            // discard tickets with timeout 0
            int ticketLifetime = (int)(nstm.sessionTicket.expires -
                    nstm.sessionTicket.creationTime) / 1000;
            if (ticketLifetime <= 0 ||
                ticketLifetime > MAX_TICKET_LIFETIME) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "Discarding NewSessionTicket with lifetime " +
                            ticketLifetime, nstm);
                }

                return;
            }

            // Add the ticket to the session.
            ((SSLSessionImpl.ClientSession)tc.conSession)
                    .putSessionTicket(nstm.sessionTicket);
        }
    }

    private static SecretKey derivePreSharedKey(
            TransportContext tc, byte[] ticketNonce) throws IOException {
        SSLTrafficKeyDerivation kdg =
                SSLTrafficKeyDerivation.valueOf(tc.protocolVersion);
        if (kdg == null) {      // unlikely
            throw tc.fatal(Alert.INTERNAL_ERROR,
                    "Not supported key derivation: " + tc.protocolVersion);
        }

        SSLKeyDerivation skd = kdg.createKeyDerivation(
                tc, tc.resumptionMasterSecret);
        if (skd == null) {      // unlikely
            throw tc.fatal(Alert.INTERNAL_ERROR, "no key derivation");
        }

        return skd.deriveKey("TlsResumption", new IvParameterSpec(ticketNonce));
    }
}
