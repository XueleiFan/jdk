/*
 * Copyright (c) 2015, 2020, Oracle and/or its affiliates. All rights reserved.
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
import java.security.*;
import java.text.MessageFormat;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLProtocolException;
import sun.security.ssl.ClientHello.ClientHelloMessage;
import sun.security.ssl.NewSessionTicket.SessionTicket;
import sun.security.ssl.NewSessionTicket.T13SessionTicket;
import sun.security.ssl.SSLExtension.ExtensionConsumer;
import sun.security.ssl.SSLExtension.SSLExtensionSpec;
import sun.security.ssl.SSLHandshake.HandshakeMessage;
import sun.security.ssl.SSLSessionImpl.ClientSession;
import sun.security.ssl.SSLSessionImpl.ServerSession;
import sun.security.ssl.ServerHello.ServerHelloMessage;
import sun.security.util.HexDumpEncoder;

import static sun.security.ssl.SSLExtension.*;

/**
 * Pack of the "pre_shared_key" extension.
 */
final class PreSharedKeyExtension {
    static final HandshakeProducer chNetworkProducer =
            new CHPreSharedKeyProducer();
    static final ExtensionConsumer chOnLoadConsumer =
            new CHPreSharedKeyConsumer();
    static final HandshakeAbsence chOnLoadAbsence =
            new CHPreSharedKeyOnLoadAbsence();
    static final HandshakeConsumer chOnTradeConsumer =
            new CHPreSharedKeyUpdate();
    static final HandshakeAbsence chOnTradAbsence =
            new CHPreSharedKeyOnTradeAbsence();
    static final SSLStringizer chStringizer =
            new CHPreSharedKeyStringizer();

    static final HandshakeProducer shNetworkProducer =
            new SHPreSharedKeyProducer();
    static final ExtensionConsumer shOnLoadConsumer =
            new SHPreSharedKeyConsumer();
    static final HandshakeAbsence shOnLoadAbsence =
            new SHPreSharedKeyAbsence();
    static final SSLStringizer shStringizer =
            new SHPreSharedKeyStringizer();

    // The PskIdentity structure defined in RFC 8446:
    //      struct {
    //          opaque identity<1..2^16-1>;
    //          uint32 obfuscated_ticket_age;
    //      } PskIdentity;
    private static final class PskIdentity {
        final byte[] identity;
        final int obfuscatedAge;

        PskIdentity(byte[] identity, int obfuscatedAge) {
            this.identity = identity;
            this.obfuscatedAge = obfuscatedAge;
        }

        int getEncodedLength() {
            return 2 + identity.length + 4;
        }

        void writeEncoded(ByteBuffer m) throws IOException {
            Record.putBytes16(m, identity);
            Record.putInt32(m, obfuscatedAge);
        }

        @Override
        public String toString() {
            return "{" + Utilities.toHexString(identity) + ", " +
                obfuscatedAge + "}";
        }
    }

    // The "pre_shared_key" extension in ClientHello handshake message.
    //      struct {
    //          PskIdentity identities<7..2^16-1>;
    //          PskBinderEntry binders<33..2^16-1>;
    //      } OfferedPsks;
    private static final
            class CHPreSharedKeySpec implements SSLExtensionSpec {
        final PskIdentity[] identities;
        final byte[][] binders;

        CHPreSharedKeySpec(PskIdentity identity, byte[] binder) {
            this.identities = new PskIdentity[] {
                    identity
                };
            this.binders = new byte[][]{
                    binder
                };
        }

        CHPreSharedKeySpec(TransportContext tc,
                ByteBuffer m) throws IOException {
            if (m.remaining() < 44) {
                throw tc.fatal(Alert.DECODE_ERROR, new SSLProtocolException(
                    "Invalid pre_shared_key extension: " +
                    "insufficient data (length=" + m.remaining() + ")"));
            }

            // Read the identifies.
            int idEncodedLength = Record.getInt16(m);
            if (m.remaining() < idEncodedLength) {
                throw tc.fatal(Alert.DECODE_ERROR, new SSLProtocolException(
                    "Invalid pre_shared_key extension: " +
                    "insufficient identities (length=" +
                    idEncodedLength + ")"));
            }

            LinkedList<PskIdentity> identities = new LinkedList<>();
            int reservedLimit = m.limit();
            m.limit(m.position() + idEncodedLength);
            while (m.hasRemaining()) {
                if (m.remaining() < 7) {
                    throw tc.fatal(Alert.DECODE_ERROR, new SSLProtocolException(
                        "Invalid pre_shared_key extension: insufficient PSK " +
                        "identity (length=" + m.remaining() + ")"));
                }

                byte[] identity = Record.getBytes16(m);
                if (identity.length < 1) {
                    throw tc.fatal(Alert.DECODE_ERROR, new SSLProtocolException(
                        "Invalid pre_shared_key extension: insufficient " +
                        "identity (length=" + identity.length + ")"));
                }

                if (m.remaining() < 4) {
                    throw tc.fatal(Alert.DECODE_ERROR, new SSLProtocolException(
                        "Invalid pre_shared_key extension: insufficient " +
                        "data for obfuscated ticket age (length=" +
                        m.remaining() + ")"));
                }
                int obfuscatedTicketAge = Record.getInt32(m);

                identities.add(new PskIdentity(identity, obfuscatedTicketAge));
            }
            m.limit(reservedLimit);

            // Read the binders.
            if (m.remaining() < 35) {
                throw tc.fatal(Alert.DECODE_ERROR, new SSLProtocolException(
                    "Invalid pre_shared_key extension: " +
                    "insufficient binders data (length=" +
                    m.remaining() + ")"));
            }

            int bindersEncodedLen = Record.getInt16(m);
            if (m.remaining() != bindersEncodedLen) {
                throw tc.fatal(Alert.DECODE_ERROR, new SSLProtocolException(
                    "Invalid pre_shared_key extension: unknown extra data"));
            }

            LinkedList<byte[]> binders = new LinkedList<>();
            while (m.hasRemaining()) {
                if (bindersEncodedLen < 33) {
                    throw tc.fatal(Alert.DECODE_ERROR, new SSLProtocolException(
                        "Invalid pre_shared_key extension: " +
                        "insufficient binders (length=" +
                        m.remaining() + ")"));
                }
                byte[] binder = Record.getBytes8(m);
                binders.add(binder);
            }

            if (binders.size() != identities.size()) {
                throw tc.fatal(Alert.DECODE_ERROR, new SSLProtocolException(
                        "Invalid pre_shared_key extension: " +
                        "unmatched identities and binders " +
                        "(identities.length=" + identities.size() +
                        ", binders.length=" + binders.size() + ")"));
            }

            this.identities = identities.toArray(new PskIdentity[0]);
            this.binders = binders.toArray(new byte[0][]);
        }

        int encodedBinderSize() {
            int encodedSize = 2;
            for (byte[] curBinder : binders) {
                encodedSize += curBinder.length;
            }

            return encodedSize;
        }

        byte[] encode() throws IOException {
            int identitiesSize = 0;
            for (PskIdentity pskIdentity : identities) {
                identitiesSize += pskIdentity.getEncodedLength();
            }

            int bindersSize = 0;
            for (byte[] binder : binders) {
                bindersSize += 1 + binder.length;
            }

            int extDataSize = 4 + identitiesSize + bindersSize;
            byte[] buffer = new byte[extDataSize];
            ByteBuffer m = ByteBuffer.wrap(buffer);

            Record.putInt16(m, identitiesSize);
            for (PskIdentity pskIdentity : identities) {
                pskIdentity.writeEncoded(m);
            }

            Record.putInt16(m, bindersSize);
            for (byte[] curBinder : binders) {
                Record.putBytes8(m, curBinder);
            }

            return buffer;
        }

        @Override
        public String toString() {
            MessageFormat messageFormat = new MessageFormat(
                "\"PreSharedKey\": '{'\n" +
                "  \"identities\": '{'\n" +
                "{0}\n" +
                "  '}'\n" +
                "  \"binders\": '{'\n" +
                "{1}\n" +
                "  '}'\n" +
                "'}'",
                Locale.ENGLISH);

            Object[] messageFields = {
                Utilities.indent(identitiesString()),
                Utilities.indent(bindersString())
            };

            return messageFormat.format(messageFields);
        }

        private String identitiesString() {
            HexDumpEncoder hexEncoder = new HexDumpEncoder();
            StringBuilder result = new StringBuilder();
            for (PskIdentity curId : identities) {
                result.append("  {\n")
                      .append(Utilities.indent(
                            hexEncoder.encode(curId.identity), "    "))
                       .append("\n  }\n");
            }

            return result.toString();
        }

        private String bindersString() {
            HexDumpEncoder hexEncoder = new HexDumpEncoder();
            StringBuilder result = new StringBuilder();
            for (byte[] curBinder : binders) {
                result.append("  {\n")
                        .append(Utilities.indent(
                                hexEncoder.encode(curBinder), "    "))
                        .append("\n  }\n");
            }

            return result.toString();
        }
    }

    private static final
            class CHPreSharedKeyStringizer implements SSLStringizer {
        @Override
        public String toString(TransportContext tc, ByteBuffer buffer) {
            try {
                return (new CHPreSharedKeySpec(tc, buffer)).toString();
            } catch (Exception ex) {
                // For debug logging only, so please swallow exceptions.
                return ex.getMessage();
            }
        }
    }

    // The "pre_shared_key" extension in ServerHello handshake message.
    //      uint16 selected_identity;
    private static final
            class SHPreSharedKeySpec implements SSLExtensionSpec {
        final short selectedIdentity;

        SHPreSharedKeySpec(short selectedIdentity) {
            this.selectedIdentity = selectedIdentity;
        }

        SHPreSharedKeySpec(TransportContext tc,
                ByteBuffer m) throws IOException {
            if (m.remaining() != 2) {
                throw tc.fatal(Alert.DECODE_ERROR,
                        new SSLProtocolException(
                    "Invalid pre_shared_key extension data (length=" +
                    m.remaining() + ")"));
            }

            this.selectedIdentity = (short)Record.getInt16(m);
        }

        byte[] getEncoded() {
            return new byte[] {
                (byte)((selectedIdentity >> 8) & 0xFF),
                (byte)(selectedIdentity & 0xFF)
            };
        }

        @Override
        public String toString() {
            MessageFormat messageFormat = new MessageFormat(
                "\"PreSharedKey\": '{'\n" +
                "  \"selected_identity\"      : \"{0}\",\n" +
                "'}'",
                Locale.ENGLISH);

            Object[] messageFields = {
                Utilities.byte16HexString(selectedIdentity)
            };

            return messageFormat.format(messageFields);
        }
    }

    private static final
            class SHPreSharedKeyStringizer implements SSLStringizer {
        @Override
        public String toString(TransportContext tc, ByteBuffer buffer) {
            try {
                return (new SHPreSharedKeySpec(tc, buffer)).toString();
            } catch (Exception ex) {
                // For debug logging only, so please swallow exceptions.
                return ex.getMessage();
            }
        }
    }

    /**
     * Network data producer of the "pre_shared_key" extension in a ClientHello
     * handshake message.
     */
    private static final
    class CHPreSharedKeyProducer implements HandshakeProducer {
        // Please DON't write to these byte arrays!!!
        private static final byte[] sha256NominalBinder = new byte[32];
        private static final byte[] sha384NominalBinder = new byte[48];
        // private static final byte[] sha512NominalBinder = new byte[64];

        // Prevent instantiation of this class.
        private CHPreSharedKeyProducer() {
            // blank
        }

        @Override
        public byte[] produce(
                ConnectionContext context,
                HandshakeMessage message) throws IOException {

            // The producing happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            // Is it a supported and enabled extension?
            if (!chc.sslConfig.isAvailable(SSLExtension.CH_PRE_SHARED_KEY)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "Ignore unavailable pre_shared_key extension in " +
                            "ClientHello, and disable session resumption");
                }

                // no resumption
                chc.isResumption = false;
                chc.resumingSession = null;

                return null;
            }

            if (!chc.isResumption || chc.resumingSession == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                        "No pre-share-key extension: not session resumption");
                }

                return null;
            }

            if (!chc.resumingSession.protocolVersion.useTLS13PlusSpec()) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "Ignore pre-share-key extension: " +
                            "the negotiated protocol version is " +
                            chc.resumingSession.protocolVersion);
                }

                return null;
            }

            // Is it reproducing this extension because of HelloRetryRequest
            // or pre-share key binders calculation?
            CHPreSharedKeySpec spec =
                    (CHPreSharedKeySpec)chc.handshakeExtensions.get(
                            SSLExtension.CH_PRE_SHARED_KEY);
            if (spec != null) {
                if (message instanceof ClientHelloMessage) {
                    // Reproduce for pre-share key binders calculation.
                    return reproduce(chc, (ClientHelloMessage)message, spec);
                } else if (message instanceof ServerHelloMessage) {
                    // Reproduce for HelloRetryRequest.
                    return reproduce(chc,
                            (ServerHelloMessage)message, spec);
                } else {
                    // unlikely
                    throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE,
                            "Unexpected handshake message (" +
                                    message.handshakeType().name +
                                    ") for the pre_shared_key extension");
                }
            } else if (message instanceof ClientHelloMessage) {
                // The initial nominal producing of this extension.
                return nominalProduce(chc, (ClientHelloMessage)message);
            } else {
                // unlikely
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE,
                        "Unexpected handshake message (" +
                                message.handshakeType().name +
                                ") for the pre_shared_key extension");
            }
        }

        // The initial nominal producing of this extension, which file the
        // binders with zeros.
        private byte[] nominalProduce(
                ClientHandshakeContext chc,
                ClientHelloMessage clientHello) throws IOException {
            // Prepare the identities.
            SessionTicket sessionTicket =
                    ((ClientSession)chc.resumingSession).getSessionTicket();
            if (!(sessionTicket instanceof T13SessionTicket)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "No pre-share-key extension: " +
                            "no session ticket available: " + sessionTicket);
                }

                // no resumption
                chc.isResumption = false;
                chc.resumingSession = null;

                return null;
            }

            T13SessionTicket t13st = (T13SessionTicket)sessionTicket;

            int ticketAge =
                    (int)(System.currentTimeMillis() - t13st.creationTime);
            int obfuscatedAge = ticketAge + (t13st.ticketAgeAdd);

            // Prepare the binders.
            byte[] binder = null;
            switch (chc.resumingSession.getSuite().hashAlg) {
                case H_SHA256:
                    binder = sha256NominalBinder;
                    break;
                case H_SHA384:
                    binder = sha384NominalBinder;
                    break;
                case H_NONE:
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine(
                                "No pre-share-key extension: " +
                                "no negotiated cipher suite");
                    }
                    chc.isResumption = false;
                    chc.resumingSession = null;

                    return null;
            }

            // Set the negotiated cipher suite for key derivation.
            chc.negotiatedCipherSuite = chc.resumingSession.cipherSuite;

            // Derive the early secret.
            SecretKey earlySecret = SSLPseudorandomKeyDerivation
                    .of(chc, null, t13st.preSharedKey)
                    .deriveKey("TlsEarlySecret", null);

            // Set the handshake key derivation to use pre-shared key.
            chc.handshakeKeyDerivation =
                    new SSLSecretDerivation(chc, earlySecret);

            // Create the pre-shared key spec.
            CHPreSharedKeySpec spec = new CHPreSharedKeySpec(
                    new PskIdentity(t13st.ticket, obfuscatedAge),
                    binder);
            chc.handshakeExtensions.put(CH_PRE_SHARED_KEY, spec);

            return spec.encode();
        }

        // Reproduce the extension for pre-share key binders calculation.
        private byte[] reproduce(
                ClientHandshakeContext chc,
                ClientHelloMessage clientHello,
                CHPreSharedKeySpec spec) throws IOException {

            // Calculate and replace the binder.
            spec.binders[0] = createBinder(chc, clientHello, spec);

            return spec.encode();
        }

        // Reproduce the extension for HelloRetryRequest.
        private byte[] reproduce(
                ClientHandshakeContext chc,
                ServerHelloMessage helloRetryRequest,
                CHPreSharedKeySpec spec) throws IOException {
            // Check if the resuming cipher suite is selected in the
            // HelloRetryRequest handshake message.
            CipherSuite resumingCipherSuite = chc.resumingSession.getSuite();
            if (chc.negotiatedCipherSuite != resumingCipherSuite ||
                    helloRetryRequest.cipherSuite != resumingCipherSuite) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "The resuming cipher suite is not selected " +
                            "selected in the HelloRetryRequest message.");
                }

                chc.isResumption = false;
                chc.resumingSession = null;
                return null;
            }

            // Calculate and replace the binder.
            spec.binders[0] =
                    createBinder(chc, chc.initialClientHelloMsg, spec);

            return spec.encode();
        }

        private static byte[] createBinder(
                ClientHandshakeContext chc,
                ClientHelloMessage clientHello,
                CHPreSharedKeySpec spec) throws IOException {

            // Calculate and replace the binder.
            HandshakeHash handshakeHash = chc.handshakeHash.copy();
            handshakeHash.determine(
                    chc.resumingSession.protocolVersion,
                    chc.resumingSession.cipherSuite);
            HandshakeOutStream hos = new HandshakeOutStream(null);
            clientHello.write(hos);

            // Exclude the binders bytes for the handshake hash calculation.
            hos.accept(handshakeHash, 0, hos.size() - spec.encodedBinderSize());
            handshakeHash.update();

            // Derive the binder key.
            SSLTrafficKeyDerivation kdg =
                    SSLTrafficKeyDerivation.valueOf(ProtocolVersion.TLS13);
            if (kdg == null) {      // unlikely
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR,
                        "Not supported key derivation for TLS 1.3");
            }

            SecretKey binderKey = chc.handshakeKeyDerivation
                    .deriveKey("TlsResBinderKey", null);
            SecretKey finishedKey = kdg.createKeyDerivation(chc, binderKey)
                    .deriveKey("TlsFinished", null);

            String hmacAlg = "Hmac" +
                    chc.negotiatedCipherSuite.hashAlg.name.replace("-", "");
            try {
                Mac hmac = Mac.getInstance(hmacAlg);
                hmac.init(finishedKey);
                return hmac.doFinal(handshakeHash.digest());
            } catch (NoSuchAlgorithmException |InvalidKeyException ex) {
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR,
                        "Failed to generate binder", ex);
            }
        }
    }

    /**
     * Network data consumer of a "pre_shared_key" extension in the ClientHello
     * handshake message.
     */
    private static final
            class CHPreSharedKeyConsumer implements ExtensionConsumer {
        // Prevent instantiation of this class.
        private CHPreSharedKeyConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                            HandshakeMessage message,
                            ByteBuffer buffer) throws IOException {
            // The consuming happens in server side only.
            ClientHelloMessage clientHello = (ClientHelloMessage) message;
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            // Is it a supported and enabled extension?
            if (!shc.sslConfig.isAvailable(SSLExtension.CH_PRE_SHARED_KEY) ||
                !shc.sslConfig.isAvailable(SSLExtension.SH_PRE_SHARED_KEY)) {

                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "Ignore unavailable pre_shared_key extension, " +
                            "and disable session resumption");
                }

                // no resumption
                shc.isResumption = false;
                shc.resumingSession = null;

                return;
            }

            // The "psk_key_exchange_modes" extension should have been loaded.
            if (!shc.handshakeExtensions.containsKey(
                    SSLExtension.PSK_KEY_EXCHANGE_MODES)) {
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                        "Client sent PSK but not PSK modes, or the PSK " +
                                "extension is not the last extension");
            }

            // Is resumption enabled?  The "psk_key_exchange_modes" extension
            // may have invalidated the session.
            if (!shc.isResumption) {     // resumingSession may not be set
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "Ignore pre_shared_key extension: " +
                            "no session resumption");
                }

                return;
            }

            // Make sure that the server handshake context's localSupportedSignAlgs
            // field is populated.  This is particularly important when
            // client authentication was used in an initial session and it is
            // now being resumed.
            if (shc.localSupportedSignAlgs == null) {
                shc.localSupportedSignAlgs =
                        SignatureScheme.getSupportedAlgorithms(
                                shc.sslConfig,
                                shc.algorithmConstraints, shc.activeProtocols);
            }

            // Parse the extension.
            CHPreSharedKeySpec spec =
                    new CHPreSharedKeySpec(shc.conContext, buffer);

            int selectedId = 0;
            ServerSession ticketSession = null;
            SecretKey preSharedKey = null;
            SessionTicketManager stm = shc.sslContext.getTicketManager();
            for (int i = 0; i < spec.identities.length; i++) {
                PskIdentity pskId = spec.identities[i];
                if (pskId.identity.length > 40) {   // stateless session ticket
                    byte[] decodedTicket = stm.decodeTicket(pskId.identity);
                    if (decodedTicket == null || decodedTicket.length == 0) {
                        continue;
                    }

                    Map.Entry<SecretKey, ServerSession> decodedSession =
                            ServerSession.decodeT13StatelessTicket(
                                    shc, decodedTicket);
                    if (decodedSession == null) {
                        continue;
                    }

                    preSharedKey = decodedSession.getKey();
                    if (preSharedKey == null) {
                        continue;
                    }

                    ticketSession = decodedSession.getValue();
                } else {        // stateful session ticket, use session cache
                    long ticketId = Utilities.toLong(pskId.identity);
                    byte[] sessionId = Arrays.copyOfRange(
                            pskId.identity, 8, pskId.identity.length);
                    ServerSession serverSession =
                            (ServerSession)shc.sslContext
                                    .serverCache.getSession(sessionId);
                    if (serverSession == null ||
                            serverSession.cannotResume(shc)) {
                        continue;
                    }

                    T13SessionTicket t13st =
                            serverSession.getStatefulSessionTicket(ticketId);
                    if (t13st == null) {
                        continue;
                    }

                    preSharedKey = t13st.preSharedKey;
                    if (preSharedKey == null) {
                        continue;
                    }
                    ticketSession = serverSession;
                }

                if (ticketSession != null) {
                    if (ticketSession.cannotResume(shc)) {
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                            SSLLogger.fine(
                                    "Retrieved session cannot be resumed",
                                    ticketSession);
                        }

                        ticketSession = null;
                    } else {
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                            SSLLogger.fine(
                                    "Retrieved resuming session (pskId = " +
                                    selectedId + ")", ticketSession);
                        }
                        selectedId = i;
                        break;
                    }
                }
            }

            if (ticketSession == null) {
                // no resumption
                shc.isResumption = false;
                shc.resumingSession = null;

                return;
            }

            // Derive the early secret.
            SecretKey earlySecret = SSLPseudorandomKeyDerivation
                    .of(shc, null, preSharedKey)
                    .deriveKey("TlsEarlySecret", null);

            // Set the handshake key derivation to use pre-shared key.
            shc.handshakeKeyDerivation =
                    new SSLSecretDerivation(shc, earlySecret);

            // check the binder.
            byte[] binder = createBinder(shc, spec);
            if (!Arrays.equals(binder, spec.binders[selectedId])) {
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                        "Incorrect PSK binder value");
            }

            // update the context
            shc.resumingSession = ticketSession;
            shc.handshakeExtensions.put(
                    SSLExtension.CH_PRE_SHARED_KEY, spec);
            shc.handshakeExtensions.put(SH_PRE_SHARED_KEY,
                    new SHPreSharedKeySpec((short)selectedId));
        }

        private static byte[] createBinder(
                ServerHandshakeContext shc,
                CHPreSharedKeySpec spec) throws IOException {

            // Truncate the ClientHello message for the binder calculation.
            HandshakeHash handshakeHash = shc.handshakeHash.copy();
            handshakeHash.determine(
                    shc.negotiatedProtocol, shc.negotiatedCipherSuite);
            handshakeHash.updateWithLastMessageTruncated(spec.encodedBinderSize());

            // Derive the binder key.
            SSLTrafficKeyDerivation kdg =
                    SSLTrafficKeyDerivation.valueOf(ProtocolVersion.TLS13);
            if (kdg == null) {      // unlikely
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR,
                        "Not supported key derivation for TLS 1.3");
            }

            SecretKey binderKey = shc.handshakeKeyDerivation
                    .deriveKey("TlsResBinderKey", null);
            SecretKey finishedKey = kdg.createKeyDerivation(shc, binderKey)
                    .deriveKey("TlsFinished", null);

            String hmacAlg = "Hmac" +
                    shc.negotiatedCipherSuite.hashAlg.name.replace("-", "");
            try {
                Mac hmac = Mac.getInstance(hmacAlg);
                hmac.init(finishedKey);
                return hmac.doFinal(handshakeHash.digest());
            } catch (NoSuchAlgorithmException |InvalidKeyException ex) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR,
                        "Failed to generate binder", ex);
            }
        }
    }

    private static final
            class CHPreSharedKeyUpdate implements HandshakeConsumer {
        // Prevent instantiation of this class.
        private CHPreSharedKeyUpdate() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The consuming happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            if (!shc.handshakeExtensions.containsKey(
                    SSLExtension.CH_KEY_SHARE)) {
                // No session resumption is allowed if no key_share extension.
                shc.resumingSession = null;
                shc.isResumption = false;

                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "No key_share extension, " +
                            "no session resumption is allowed.");
                }
            }
        }
    }

    private static final
            class CHPreSharedKeyOnLoadAbsence implements HandshakeAbsence {
        @Override
        public void absent(ConnectionContext context,
                           HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            // Resumption is only determined by PSK, when enabled
            shc.resumingSession = null;
            shc.isResumption = false;

            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                        "No pre-shared key extension, no session resumption.");
            }
        }
    }

    /**
     * The absence processing if the extension is not present in
     * a ClientHello handshake message.
     */
    private static final class CHPreSharedKeyOnTradeAbsence
            implements HandshakeAbsence {
        @Override
        public void absent(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The producing happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            // A client is considered to be attempting to negotiate using this
            // specification if the ClientHello contains a "supported_versions"
            // extension with 0x0304 contained in its body.  Such a ClientHello
            // message MUST meet the following requirements:
            //   -  If not containing a "pre_shared_key" extension, it MUST
            //      contain both a "signature_algorithms" extension and a
            //      "supported_groups" extension.
            if (shc.negotiatedProtocol.useTLS13PlusSpec() &&
                    (!shc.handshakeExtensions.containsKey(
                            SSLExtension.CH_SIGNATURE_ALGORITHMS) ||
                     !shc.handshakeExtensions.containsKey(
                            SSLExtension.CH_SUPPORTED_GROUPS))) {
                throw shc.conContext.fatal(Alert.MISSING_EXTENSION,
                    "No supported_groups or signature_algorithms extension " +
                    "when pre_shared_key extension is not present");
            }
        }
    }

    private static final
    class SHPreSharedKeyProducer implements HandshakeProducer {
        // Prevent instantiation of this class.
        private SHPreSharedKeyProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                              HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            // Is it a supported and enabled extension?
            if (!shc.sslConfig.isAvailable(SSLExtension.CH_PRE_SHARED_KEY) ||
                !shc.sslConfig.isAvailable(SSLExtension.SH_PRE_SHARED_KEY)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "Ignore unavailable pre_shared_key extension in " +
                            "ServerHello, and disable session resumption");
                }

                // no resumption
                shc.isResumption = false;
                shc.resumingSession = null;

                return null;
            }

            // Note: the spec had been generated while loading the extension in
            // ClientHello handshake message.
            SHPreSharedKeySpec spec = (SHPreSharedKeySpec)
                    shc.handshakeExtensions.get(SH_PRE_SHARED_KEY);
            if (spec == null) {
                return null;
            }

            return spec.getEncoded();
        }
    }

    private static final
            class SHPreSharedKeyConsumer implements ExtensionConsumer {
        // Prevent instantiation of this class.
        private SHPreSharedKeyConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
            HandshakeMessage message, ByteBuffer buffer) throws IOException {
            // The consuming happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            // Is it a response of the specific request?
            if (!chc.handshakeExtensions.containsKey(
                    SSLExtension.CH_PRE_SHARED_KEY)) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE,
                    "Server sent unexpected pre_shared_key extension");
            }

            SHPreSharedKeySpec shPsk =
                    new SHPreSharedKeySpec(chc.conContext, buffer);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                    "Received pre_shared_key extension: ", shPsk);
            }

            if (shPsk.selectedIdentity != 0) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "Selected identity index is not in correct range.");
            }
        }
    }

    private static final
            class SHPreSharedKeyAbsence implements HandshakeAbsence {
        @Override
        public void absent(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Handling pre_shared_key absence.");
            }

            // The server refused to resume, or the client did not
            // request 1.3 resumption.
            chc.resumingSession = null;
            chc.isResumption = false;
        }
    }
}
