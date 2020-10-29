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
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLProtocolException;

import sun.security.ssl.SSLHandshake.HandshakeMessage;
import sun.security.ssl.SSLSessionImpl.ClientSession;
import sun.security.ssl.SSLSessionImpl.ServerSession;
import sun.security.ssl.SupportedVersionsExtension.CHSupportedVersionsSpec;

/**
 * Pack of the ClientHello handshake message.
 */
final class ClientHello {
    static final SSLProducer kickstartProducer =
        new ClientHelloKickstartProducer();
    static final SSLConsumer handshakeConsumer =
        new ClientHelloConsumer();
    static final HandshakeProducer handshakeProducer =
        new ClientHelloProducer();

    private static final HandshakeConsumer t12HandshakeConsumer =
            new T12ClientHelloConsumer();
    private static final HandshakeConsumer t13HandshakeConsumer =
            new T13ClientHelloConsumer();
    private static final HandshakeConsumer d12HandshakeConsumer =
            new D12ClientHelloConsumer();
    private static final HandshakeConsumer d13HandshakeConsumer =
            new D13ClientHelloConsumer();

    /**
     * The ClientHello handshake message.
     *
     * See RFC 5264/4346/2246/6347 for the specifications.
     */
    static final class ClientHelloMessage extends HandshakeMessage {
        private final boolean       isDTLS;

        final int                   clientVersion;
        final RandomCookie          clientRandom;

        // The sessionId field could be reset by the handshake producer,
        // otherwise, it could be final.
        SessionId                   sessionId;

        private byte[]              cookie;         // DTLS only
        final int[]                 cipherSuiteIds;
        final List<CipherSuite>     cipherSuites;   // known cipher suites only
        final byte[]                compressionMethod;
        final SSLExtensions         extensions;

        private static final byte[]  NULL_COMPRESSION = new byte[] {0};

        ClientHelloMessage(HandshakeContext hc,
                int clientVersion, SessionId sessionId,
                List<CipherSuite> cipherSuites, SecureRandom generator) {
            super(hc.conContext);
            this.isDTLS = hc.sslContext.isDTLS();

            this.clientVersion = clientVersion;
            this.clientRandom = new RandomCookie(generator);
            this.sessionId = sessionId;
            if (isDTLS) {
                this.cookie = new byte[0];
            } else {
                this.cookie = null;
            }

            this.cipherSuites = cipherSuites;
            this.cipherSuiteIds = getCipherSuiteIds(cipherSuites);
            this.extensions = new SSLExtensions(this);

            // Don't support compression.
            this.compressionMethod = NULL_COMPRESSION;
        }

        ClientHelloMessage(HandshakeContext hc, ByteBuffer m,
                SSLExtension[] supportedExtensions) throws IOException {
            super(hc.conContext);
            this.isDTLS = hc.sslContext.isDTLS();

            this.clientVersion = ((m.get() & 0xFF) << 8) | (m.get() & 0xFF);
            this.clientRandom = new RandomCookie(m);
            this.sessionId = new SessionId(Record.getBytes8(m));
            try {
                sessionId.checkLength(clientVersion);
            } catch (SSLProtocolException ex) {
                throw hc.conContext.fatal(
                        Alert.ILLEGAL_PARAMETER, ex);
            }
            if (isDTLS) {
                this.cookie = Record.getBytes8(m);
            } else {
                this.cookie = null;
            }

            byte[] encodedIds = Record.getBytes16(m);
            if (encodedIds.length == 0 || (encodedIds.length & 0x01) != 0) {
                throw hc.conContext.fatal(
                        Alert.ILLEGAL_PARAMETER,
                        "Invalid ClientHello message");
            }

            this.cipherSuiteIds = new int[encodedIds.length >> 1];
            for (int i = 0, j = 0; i < encodedIds.length; i++, j++) {
                cipherSuiteIds[j] =
                    ((encodedIds[i++] & 0xFF) << 8) | (encodedIds[i] & 0xFF);
            }
            this.cipherSuites = getCipherSuites(cipherSuiteIds);

            this.compressionMethod = Record.getBytes8(m);

            // In TLS 1.3, use of certain extensions is mandatory.
            if (m.hasRemaining()) {
                this.extensions =
                        new SSLExtensions(this, m, supportedExtensions);
            } else {
                this.extensions = new SSLExtensions(this);
            }
        }

        void setHelloCookie(byte[] cookie) {
            this.cookie = cookie;
        }

        // DTLS 1.0/1.2, for cookie generation.
        byte[] getHelloCookieBytes() {
            HandshakeOutStream hos = new HandshakeOutStream(null);
            try {
                // copied from send() method
                hos.putInt8((byte)((clientVersion >>> 8) & 0xFF));
                hos.putInt8((byte)(clientVersion & 0xFF));
                hos.write(clientRandom.randomBytes, 0, 32);
                hos.putBytes8(sessionId.getId());
                // ignore cookie
                hos.putBytes16(getEncodedCipherSuites());
                hos.putBytes8(compressionMethod);
                extensions.send(hos);       // In TLS 1.3, use of certain
                                            // extensions is mandatory.
            } catch (IOException ioe) {
                // unlikely
            }

            return hos.toByteArray();
        }

        // (D)TLS 1.3, for cookie generation.
        byte[] getHeaderBytes() {
            HandshakeOutStream hos = new HandshakeOutStream(null);
            try {
                // copied from send() method
                hos.putInt8((byte)((clientVersion >>> 8) & 0xFF));
                hos.putInt8((byte)(clientVersion & 0xFF));
                hos.write(clientRandom.randomBytes, 0, 32);
                hos.putBytes8(sessionId.getId());
                hos.putBytes16(getEncodedCipherSuites());
                hos.putBytes8(compressionMethod);
            } catch (IOException ioe) {
                // unlikely
            }

            return hos.toByteArray();
        }

        private static int[] getCipherSuiteIds(
                List<CipherSuite> cipherSuites) {
            if (cipherSuites != null) {
                int[] ids = new int[cipherSuites.size()];
                int i = 0;
                for (CipherSuite cipherSuite : cipherSuites) {
                    ids[i++] = cipherSuite.id;
                }

                return ids;
            }

            return new int[0];
        }

        private static List<CipherSuite> getCipherSuites(int[] ids) {
            List<CipherSuite> cipherSuites = new LinkedList<>();
            for (int id : ids) {
                CipherSuite cipherSuite = CipherSuite.valueOf(id);
                if (cipherSuite != null) {
                    cipherSuites.add(cipherSuite);
                }
            }

            return Collections.unmodifiableList(cipherSuites);
        }

        private List<String> getCipherSuiteNames() {
            List<String> names = new LinkedList<>();
            for (int id : cipherSuiteIds) {
                names.add(CipherSuite.nameOf(id) +
                        "(" + Utilities.byte16HexString(id) + ")");
            }

            return names;
        }

        private byte[] getEncodedCipherSuites() {
            byte[] encoded = new byte[cipherSuiteIds.length << 1];
            int i = 0;
            for (int id : cipherSuiteIds) {
                encoded[i++] = (byte)(id >> 8);
                encoded[i++] = (byte)id;
            }
            return encoded;
        }

        @Override
        public SSLHandshake handshakeType() {
            return SSLHandshake.CLIENT_HELLO;
        }

        @Override
        public int messageLength() {
            /*
             * Add fixed size parts of each field...
             * version + random + session + cipher + compress
             */
            return (2 + 32 + 1 + 2 + 1
                + sessionId.length()        /* ... + variable parts */
                + (isDTLS ? (1 + cookie.length) : 0)
                + (cipherSuiteIds.length * 2)
                + compressionMethod.length)
                + extensions.length();      // In TLS 1.3, use of certain
                                            // extensions is mandatory.
        }

        @Override
        public void send(HandshakeOutStream hos) throws IOException {
            hos.putInt8((byte) (clientVersion >>> 8));
            hos.putInt8((byte) clientVersion);
            hos.write(clientRandom.randomBytes, 0, 32);
            hos.putBytes8(sessionId.getId());
            if (isDTLS) {
                hos.putBytes8(cookie);
            }
            hos.putBytes16(getEncodedCipherSuites());
            hos.putBytes8(compressionMethod);

            extensions.send(hos);       // In TLS 1.3, use of certain
                                        // extensions is mandatory.
        }

        @Override
        public String toString() {
            if (isDTLS) {
                MessageFormat messageFormat = new MessageFormat(
                    "\"ClientHello\": '{'\n" +
                    "  \"client version\"      : \"{0}\",\n" +
                    "  \"random\"              : \"{1}\",\n" +
                    "  \"session id\"          : \"{2}\",\n" +
                    "  \"cookie\"              : \"{3}\",\n" +
                    "  \"cipher suites\"       : \"{4}\",\n" +
                    "  \"compression methods\" : \"{5}\",\n" +
                    "  \"extensions\"          : [\n" +
                    "{6}\n" +
                    "  ]\n" +
                    "'}'",
                    Locale.ENGLISH);
                Object[] messageFields = {
                    ProtocolVersion.nameOf(clientVersion),
                    Utilities.toHexString(clientRandom.randomBytes),
                    sessionId.toString(),
                    Utilities.toHexString(cookie),
                    getCipherSuiteNames().toString(),
                    Utilities.toHexString(compressionMethod),
                    Utilities.indent(Utilities.indent(extensions.toString()))
                };

                return messageFormat.format(messageFields);
            } else {
                MessageFormat messageFormat = new MessageFormat(
                    "\"ClientHello\": '{'\n" +
                    "  \"client version\"      : \"{0}\",\n" +
                    "  \"random\"              : \"{1}\",\n" +
                    "  \"session id\"          : \"{2}\",\n" +
                    "  \"cipher suites\"       : \"{3}\",\n" +
                    "  \"compression methods\" : \"{4}\",\n" +
                    "  \"extensions\"          : [\n" +
                    "{5}\n" +
                    "  ]\n" +
                    "'}'",
                    Locale.ENGLISH);
                Object[] messageFields = {
                    ProtocolVersion.nameOf(clientVersion),
                    Utilities.toHexString(clientRandom.randomBytes),
                    sessionId.toString(),
                    getCipherSuiteNames().toString(),
                    Utilities.toHexString(compressionMethod),
                    Utilities.indent(Utilities.indent(extensions.toString()))
                };

                return messageFormat.format(messageFields);
            }
        }
    }

    /**
     * The "ClientHello" handshake message kick start producer.
     */
    private static final
            class ClientHelloKickstartProducer implements SSLProducer {
        // Prevent instantiation of this class.
        private ClientHelloKickstartProducer() {
            // blank
        }

        // Produce kickstart handshake message.
        @Override
        public byte[] produce(ConnectionContext context) throws IOException {
            // The producing happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            // clean up this producer
            chc.handshakeProducers.remove(SSLHandshake.CLIENT_HELLO.id);

            // the max protocol version this client is supporting.
            ProtocolVersion maxProtocolVersion = chc.maximumActiveProtocol;

            // session ID of the ClientHello message
            SessionId sessionId = new SessionId(new byte[0]);

            // a list of cipher suites sent by the client
            List<CipherSuite> cipherSuites = chc.activeCipherSuites;

            //
            // Generate ClientHello with the basic configuration parameters.
            //
            ProtocolVersion clientHelloVersion = maxProtocolVersion;
            if (clientHelloVersion.useTLS13PlusSpec()) {
                // In (D)TLS 1.3, the client indicates its version preferences
                // in the "supported_versions" extension and the client_version
                // (legacy_version) field MUST be set to (D)TLS 1.2.
                if (clientHelloVersion.isDTLS) {
                    clientHelloVersion = ProtocolVersion.DTLS12;
                } else {
                    clientHelloVersion = ProtocolVersion.TLS12;
                }
            }

            ProtocolVersion minimumVersion = ProtocolVersion.NONE;
            for (ProtocolVersion pv : chc.activeProtocols) {
                if (minimumVersion == ProtocolVersion.NONE ||
                        pv.compare(minimumVersion) < 0) {
                    minimumVersion = pv;
                }
            }

            // exclude SCSV for secure renegotiation
            if (!minimumVersion.useTLS13PlusSpec()) {
                if (chc.conContext.secureRenegotiation &&
                        cipherSuites.contains(
                                CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)) {
                    // The cipherSuites may be unmodifiable
                    cipherSuites = new LinkedList<>(cipherSuites);
                    cipherSuites.remove(
                            CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
                }
            }

            // make sure there is a negotiable cipher suite.
            boolean negotiable = false;
            for (CipherSuite suite : cipherSuites) {
                if (chc.isNegotiable(suite)) {
                    negotiable = true;
                    break;
                }
            }

            if (!negotiable) {
                throw new SSLHandshakeException("No negotiable cipher suite");
            }

            // Note: use an empty sessionId here, which will be replaced later.
            ClientHelloMessage chm = new ClientHelloMessage(chc,
                    clientHelloVersion.id, sessionId, cipherSuites,
                    chc.sslContext.getSecureRandom());
            chc.clientHelloVersion = clientHelloVersion.id;

            // Produce the basic configuration extensions.
            SSLExtension[] basicConfigurationExtensions =
                    chc.sslConfig.getEnabledExtensions(
                        SSLHandshake.CLIENT_HELLO, chc.activeProtocols,
                        // selected from the specific extensions
                        Arrays.asList(
                                SSLExtension.CH_SERVER_NAME,
                                SSLExtension.CH_SUPPORTED_GROUPS,
                                SSLExtension.CH_SIGNATURE_ALGORITHMS,
                                SSLExtension.CH_SIGNATURE_ALGORITHMS_CERT,
                                SSLExtension.CH_ALPN,
                                SSLExtension.CH_SUPPORTED_VERSIONS,
                                SSLExtension.CH_CERTIFICATE_AUTHORITIES
                        ));
            chm.extensions.produce(chc, basicConfigurationExtensions);

            //
            // Try to resume an existing session.
            //
            chc.clientHelloId = createServiceId(chm,
                    chc.conContext.transport.getPeerHost(),
                    chc.conContext.transport.getPeerPort());
            ClientSession cachedSession =
                    chc.sslContext.clientCache.get(chc.clientHelloId);
            if (cachedSession != null && !cachedSession.isValid()) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                    SSLLogger.finest(
                            "Can't resume, the session is not rejoinable");
                }
                cachedSession = null;
            }

            if (cachedSession != null) {
                CipherSuite sessionSuite = cachedSession.getSuite();
                if (!chc.isNegotiable(sessionSuite)) {
                    cachedSession = null;
                    if (SSLLogger.isOn &&
                            SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest(
                            "Can't resume, unavailable session cipher suite");
                    }
                }
            }

            ProtocolVersion sessionVersion = null;
            if (cachedSession != null) {
                sessionVersion = cachedSession.getProtocolVersion();
                if (!chc.isNegotiable(sessionVersion)) {
                    cachedSession = null;
                    if (SSLLogger.isOn &&
                            SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest(
                            "Can't resume, unavailable protocol version");
                    }
                }
            }

            if (cachedSession != null &&
                !sessionVersion.useTLS13PlusSpec() &&
                SSLConfiguration.useExtendedMasterSecret) {

                boolean isEmsAvailable = chc.sslConfig.isAvailable(
                    SSLExtension.CH_EXTENDED_MASTER_SECRET, sessionVersion);
                if (isEmsAvailable && !cachedSession.useExtendedMasterSecret &&
                        !SSLConfiguration.allowLegacyResumption) {
                    // perform full handshake instead
                    //
                    // The client SHOULD NOT offer an abbreviated handshake
                    // to resume a session that does not use an extended
                    // master secret.  Instead, it SHOULD offer a full
                    // handshake.
                     cachedSession = null;
                }

                if ((cachedSession != null) &&
                        !ClientHandshakeContext.allowUnsafeServerCertChange) {
                    // It is fine to move on with abbreviate handshake if
                    // endpoint identification is enabled.
                    String identityAlg = chc.sslConfig.identificationProtocol;
                    if (identityAlg == null || identityAlg.isEmpty()) {
                        if (isEmsAvailable) {
                            if (!cachedSession.useExtendedMasterSecret) {
                                // perform full handshake instead
                                cachedSession = null;
                            }   // Otherwise, use extended master secret.
                        } else {
                            // The extended master secret extension does not
                            // apply to SSL 3.0.  Perform a full handshake
                            // instead.
                            //
                            // Note that the useExtendedMasterSecret is
                            // extended to protect SSL 3.0 connections,
                            // by discarding abbreviate handshake.
                            cachedSession = null;
                        }
                    }
                }
            }

            // ensure that the endpoint identification algorithm matches the
            // one in the session
            String identityAlg = chc.sslConfig.identificationProtocol;
            if (cachedSession != null && identityAlg != null) {
                String sessionIdentityAlg =
                    cachedSession.getIdentificationProtocol();
                if (!identityAlg.equalsIgnoreCase(sessionIdentityAlg)) {
                    if (SSLLogger.isOn &&
                    SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest("Can't resume, endpoint id" +
                            " algorithm does not match, requested: " +
                            identityAlg + ", cached: " + sessionIdentityAlg);
                    }
                    cachedSession = null;
                }
            }

            if (cachedSession != null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                    SSLLogger.finest("Try resuming session", cachedSession);
                }

                // In compatibility mode, this session_id field MUST be
                // non-empty for TLS 1.3.  A client which has a cached session
                // ID set by a pre-TLS 1.3 server SHOULD set this field to
                // that value.
                //
                // For TLS 1.2 and prior versions, always use non-empty field.
                sessionId = cachedSession.getSessionId();

                chc.isResumption = true;
                chc.resumingSession = cachedSession;
            } else {
                if (!chc.sslConfig.enableSessionCreation) {
                    throw new SSLHandshakeException(
                            "No new session is allowed and " +
                            "no existing session can be resumed");
                }

                if (maxProtocolVersion.useTLS13PlusSpec() &&
                        SSLConfiguration.useCompatibilityMode) {
                    // In compatibility mode, the TLS 1.3 legacy_session_id
                    // field MUST be non-empty, so a client not offering a
                    // pre-TLS 1.3 session MUST generate a new 32-byte value.
                    sessionId = new SessionId(chc.sslContext.getSecureRandom());
                }
            }

            // update the SessionId in ClientHello.
            chm.sessionId = sessionId;

            // cache the client random number for further using
            chc.clientHelloRandom = chm.clientRandom;
            chc.clientHelloVersion = clientHelloVersion.id;

            // Produce extensions for ClientHello handshake message.
            SSLExtension[] extTypes = chc.sslConfig.getExclusiveExtensions(
                    SSLHandshake.CLIENT_HELLO, chc.activeProtocols,
                    Arrays.asList(basicConfigurationExtensions));
            chm.extensions.produce(chc, extTypes);

            // Is it still for session resumption?  TLS 1.3 session resumption
            // may reset the session resumption status.
            if (chc.isResumption && chc.resumingSession != null) {
                // A special pre_shared_key extension producer is required to
                // calculate the binders in the pre_shared_key extension.
                //
                // Note: the pre_shared_key extension MUST be the last extension.
                if (maxProtocolVersion.useTLS13PlusSpec() &&
                        extTypes[extTypes.length - 1] ==
                                SSLExtension.CH_PRE_SHARED_KEY) {
                    chm.extensions.reproduce(chc,
                            new SSLExtension[] {
                                    SSLExtension.CH_PRE_SHARED_KEY
                            });
                }
            } else if (cachedSession != null) {
                // Previously, session resumption was assumed.  Reset the
                // the session ID filed in the ClientHello handshake message.
                //
                // Note: except pre_shared_key extension and session_ticket
                // extension, no more depends on the ClientHello handshake
                // message content.
                if (maxProtocolVersion.useTLS13PlusSpec()) {
                    sessionId = new SessionId(chc.sslContext.getSecureRandom());
                } else {
                    sessionId = new SessionId(new byte[0]);
                }

                chm.sessionId = sessionId;
            }

            // Well, now the handshake message is ready to use.
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced ClientHello handshake message", chm);
            }

            // Output the handshake message.
            chm.write(chc.handshakeOutput);
            chc.handshakeOutput.flush();

            // Reserve the initial ClientHello message for the follow on
            // cookie exchange if needed.
            chc.initialClientHelloMsg = chm;

            // What's the expected response?
            chc.handshakeConsumers.put(
                    SSLHandshake.SERVER_HELLO.id, SSLHandshake.SERVER_HELLO);
            if (chc.sslContext.isDTLS() &&
                    !minimumVersion.useTLS13PlusSpec()) {
                chc.handshakeConsumers.put(
                        SSLHandshake.HELLO_VERIFY_REQUEST.id,
                        SSLHandshake.HELLO_VERIFY_REQUEST);
            }

            // The handshake message has been delivered.
            return null;
        }
    }

    // Create the service ID per the ClientHello handshake message.
    private static SessionId createServiceId(
            ClientHelloMessage chm, String peerHost, int peerPort) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException nsae) {
            throw new RuntimeException(
                    "MessageDigest algorithm SHA-256 is not available", nsae);
        }

        md.update(peerHost == null ? new byte[0] : peerHost.getBytes());
        md.update(Utilities.toByteArray(peerPort));
        md.update(chm.getEncodedCipherSuites());

        HandshakeOutStream hos = new HandshakeOutStream(null);
        try {
            hos.putInt16(chm.clientVersion);
            chm.extensions.send(hos);
        } catch (IOException e) {
            // unlikely, just ignore
        }
        md.update(hos.toByteArray());

        return new SessionId(md.digest());
    }

    /**
     * The "ClientHello" handshake message kick start producer.  Response to
     * one of the following handshake message:
     *     HelloRequest                     (SSL 3.0/TLS 1.0/1.1/1.2)
     *     ServerHello(HelloRetryRequest)   (TLS 1.3)
     *     HelloVerifyRequest               (DTLS 1.0/1.2)
     */
    private static final
            class ClientHelloProducer implements HandshakeProducer {
        // Prevent instantiation of this class.
        private ClientHelloProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The producing happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            SSLHandshake ht = message.handshakeType();
            if (ht == null) {
                throw new UnsupportedOperationException("Not supported yet.");
            }

            switch (ht) {
                case HELLO_REQUEST:
                    // SSL 3.0/TLS 1.0/1.1/1.2
                    try {
                        chc.kickstart();
                    } catch (IOException ioe) {
                        throw chc.conContext.fatal(
                                Alert.HANDSHAKE_FAILURE, ioe);
                    }

                    // The handshake message has been delivered.
                    return null;
                case HELLO_VERIFY_REQUEST:
                    // DTLS 1.0/1.2
                    //
                    // The HelloVerifyRequest consumer should have updated the
                    // ClientHello handshake message with cookie.
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine(
                            "Produced ClientHello(cookie) handshake message",
                            chc.initialClientHelloMsg);
                    }

                    // Output the handshake message.
                    chc.initialClientHelloMsg.write(chc.handshakeOutput);
                    chc.handshakeOutput.flush();

                    // What's the expected response?
                    chc.handshakeConsumers.put(SSLHandshake.SERVER_HELLO.id,
                            SSLHandshake.SERVER_HELLO);

                    ProtocolVersion minimumVersion = ProtocolVersion.NONE;
                    for (ProtocolVersion pv : chc.activeProtocols) {
                        if (minimumVersion == ProtocolVersion.NONE ||
                                pv.compare(minimumVersion) < 0) {
                            minimumVersion = pv;
                        }
                    }
                    if (chc.sslContext.isDTLS() &&
                            !minimumVersion.useTLS13PlusSpec()) {
                        chc.handshakeConsumers.put(
                                SSLHandshake.HELLO_VERIFY_REQUEST.id,
                                SSLHandshake.HELLO_VERIFY_REQUEST);
                    }

                    // The handshake message has been delivered.
                    return null;
                case HELLO_RETRY_REQUEST:
                    // TLS 1.3
                    // The HelloRetryRequest consumer should have updated the
                    // ClientHello handshake message with cookie.
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine(
                            "Produced ClientHello(HRR) handshake message",
                            chc.initialClientHelloMsg);
                    }

                    // Output the handshake message.
                    chc.initialClientHelloMsg.write(chc.handshakeOutput);
                    chc.handshakeOutput.flush();

                    // What's the expected response?
                    chc.conContext.consumers.putIfAbsent(
                            ContentType.CHANGE_CIPHER_SPEC.id,
                            ChangeCipherSpec.t13Consumer);
                    chc.handshakeConsumers.put(SSLHandshake.SERVER_HELLO.id,
                            SSLHandshake.SERVER_HELLO);

                    // The handshake message has been delivered.
                    return null;
                default:
                    throw new UnsupportedOperationException(
                            "Not supported yet.");
            }
        }
    }

    /**
     * The "ClientHello" handshake message consumer.
     */
    private static final class ClientHelloConsumer implements SSLConsumer {
        // Prevent instantiation of this class.
        private ClientHelloConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                ByteBuffer message) throws IOException {
            // The consuming happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            // clean up this consumer
            shc.handshakeConsumers.remove(SSLHandshake.CLIENT_HELLO.id);
            if (!shc.handshakeConsumers.isEmpty()) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE,
                        "No more handshake message allowed " +
                        "in a ClientHello flight");
            }

            // Get enabled extension types in ClientHello handshake message.
            SSLExtension[] enabledExtensions =
                    shc.sslConfig.getEnabledExtensions(
                            SSLHandshake.CLIENT_HELLO);

            ClientHelloMessage chm =
                    new ClientHelloMessage(shc, message, enabledExtensions);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming ClientHello handshake message", chm);
            }

            shc.clientHelloVersion = chm.clientVersion;
            onClientHello(shc, chm);
        }

        private void onClientHello(ServerHandshakeContext context,
                ClientHelloMessage clientHello) throws IOException {
            // Negotiate protocol version.
            //
            // Check and launch SupportedVersions.
            SSLExtension[] extTypes = new SSLExtension[] {
                    SSLExtension.CH_SUPPORTED_VERSIONS
                };
            clientHello.extensions.consumeOnLoad(context, extTypes);

            ProtocolVersion negotiatedProtocol;
            CHSupportedVersionsSpec svs =
                    (CHSupportedVersionsSpec)context.handshakeExtensions.get(
                            SSLExtension.CH_SUPPORTED_VERSIONS);
            if (svs != null) {
                negotiatedProtocol =
                        negotiateProtocol(context, svs.requestedProtocols);
            } else {
                negotiatedProtocol =
                        negotiateProtocol(context, clientHello.clientVersion);
            }
            context.negotiatedProtocol = negotiatedProtocol;
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                    "Negotiated protocol version: " + negotiatedProtocol.name);
            }

            // Consume the handshake message for the specific protocol version.
            if (negotiatedProtocol.isDTLS) {
                if (negotiatedProtocol.useTLS13PlusSpec()) {
                    d13HandshakeConsumer.consume(context, clientHello);
                } else {
                    d12HandshakeConsumer.consume(context, clientHello);
                }
            } else {
                if (negotiatedProtocol.useTLS13PlusSpec()) {
                    t13HandshakeConsumer.consume(context, clientHello);
                } else {
                    t12HandshakeConsumer.consume(context, clientHello);
                }
            }
        }

        // Select a protocol version according to the
        // ClientHello.client_version.
        private ProtocolVersion negotiateProtocol(
                ServerHandshakeContext context,
                int clientHelloVersion) throws SSLException {

            // Per TLS 1.3 specification, server MUST negotiate TLS 1.2 or prior
            // even if ClientHello.client_version is 0x0304 or later.
            int chv = clientHelloVersion;
            if (context.sslContext.isDTLS()) {
                if (chv < ProtocolVersion.DTLS12.id) {
                    chv = ProtocolVersion.DTLS12.id;
                }
            } else {
                if (chv > ProtocolVersion.TLS12.id) {
                    chv = ProtocolVersion.TLS12.id;
                }
            }

            // Select a protocol version from the activated protocols.
            ProtocolVersion pv = ProtocolVersion.selectedFrom(
                    context.activeProtocols, chv);
            if (pv == null || pv == ProtocolVersion.NONE ||
                    pv == ProtocolVersion.SSL20Hello) {
                throw context.conContext.fatal(Alert.PROTOCOL_VERSION,
                    "Client requested protocol " +
                    ProtocolVersion.nameOf(clientHelloVersion) +
                    " is not enabled or supported in server context");
            }

            return pv;
        }

        // Select a protocol version according to the
        // supported_versions extension.
        private ProtocolVersion negotiateProtocol(
                ServerHandshakeContext context,
                int[] clientSupportedVersions) throws SSLException {

            // The client supported protocol versions are present in client
            // preference order.  This implementation chooses to use the server
            // preference of protocol versions instead.
            for (ProtocolVersion spv : context.activeProtocols) {
                if (spv == ProtocolVersion.SSL20Hello) {
                    continue;
                }
                for (int cpv : clientSupportedVersions) {
                    if (cpv == ProtocolVersion.SSL20Hello.id) {
                        continue;
                    }
                    if (spv.id == cpv) {
                        return spv;
                    }
                }
            }

            // No protocol version can be negotiated.
            throw context.conContext.fatal(Alert.PROTOCOL_VERSION,
                "The client supported protocol versions " + Arrays.toString(
                    ProtocolVersion.toStringArray(clientSupportedVersions)) +
                " are not accepted by server preferences " +
                context.activeProtocols);
        }
    }

    /**
     * The "ClientHello" handshake message consumer for TLS 1.2 and
     * prior SSL/TLS protocol versions.
     */
    private static final
            class T12ClientHelloConsumer implements HandshakeConsumer {
        // Prevent instantiation of this class.
        private T12ClientHelloConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The consuming happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;
            ClientHelloMessage clientHello = (ClientHelloMessage)message;

            //
            // validate
            //

            // Reject client initiated renegotiation?
            //
            // If server side should reject client-initiated renegotiation,
            // send an Alert.HANDSHAKE_FAILURE fatal alert, not a
            // no_renegotiation warning alert (no_renegotiation must be a
            // warning: RFC 2246).  no_renegotiation might seem more
            // natural at first, but warnings are not appropriate because
            // the sending party does not know how the receiving party
            // will behave.  This state must be treated as a fatal server
            // condition.
            //
            // This will not have any impact on server initiated renegotiation.
            if (shc.conContext.isNegotiated) {
                if (!shc.conContext.secureRenegotiation &&
                        !HandshakeContext.allowUnsafeRenegotiation) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                            "Unsafe renegotiation is not allowed");
                }

                if (ServerHandshakeContext.rejectClientInitiatedRenego &&
                        !shc.kickstartMessageDelivered) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                            "Client initiated renegotiation is not allowed");
                }
            }

            // Consume a Session Ticket Extension if it exists
            shc.isResumption = true;    // For the check of session ticket.
            SSLExtension[] ext = new SSLExtension[]{
                    SSLExtension.CH_SESSION_TICKET
            };
            clientHello.extensions.consumeOnLoad(shc, ext);
            if (shc.isResumption && shc.resumingSession == null) {
                // The SessionTicket extension is not available or cannot be
                // used for session resumption.  Check if the session ID can
                // be used instead.
                if (!clientHello.sessionId.isEmpty()) {
                    shc.resumingSession =
                        (SSLSessionImpl)shc.sslContext.serverCache.getSession(
                            clientHello.sessionId.getId());
                }
            }   // Otherwise, the SessionTicket extension is requested.

            // Can the session be resumed?
            if (shc.resumingSession == null ||
                    ((ServerSession)shc.resumingSession).cannotResume(shc)) {
                shc.isResumption = false;
                shc.resumingSession = null;
            }

            // cache the client random number for further using
            shc.clientHelloRandom = clientHello.clientRandom;

            // Check and launch ClientHello extensions.
            SSLExtension[] extTypes = shc.sslConfig.getExclusiveExtensions(
                    SSLHandshake.CLIENT_HELLO,
                    Collections.singletonList(SSLExtension.CH_SESSION_TICKET));
            clientHello.extensions.consumeOnLoad(shc, extTypes);

            //
            // update
            //
            if (!shc.conContext.isNegotiated) {
                shc.conContext.protocolVersion = shc.negotiatedProtocol;
                shc.conContext.outputRecord.setVersion(shc.negotiatedProtocol);
            }

            // update the responders
            //
            // Only need to ServerHello, which may add more responders later.
            // Note that ServerHello and HelloRetryRequest share the same
            // handshake type/id.  The ServerHello producer may be replaced
            // by HelloRetryRequest producer if needed.
            shc.handshakeProducers.put(SSLHandshake.SERVER_HELLO.id,
                    SSLHandshake.SERVER_HELLO);

            //
            // produce
            //
            SSLHandshake[] probableHandshakeMessages = new SSLHandshake[] {
                SSLHandshake.SERVER_HELLO,

                // full handshake messages
                SSLHandshake.CERTIFICATE,
                SSLHandshake.CERTIFICATE_STATUS,
                SSLHandshake.SERVER_KEY_EXCHANGE,
                SSLHandshake.CERTIFICATE_REQUEST,
                SSLHandshake.SERVER_HELLO_DONE,

                // abbreviated handshake messages
                SSLHandshake.FINISHED
            };

            for (SSLHandshake hs : probableHandshakeMessages) {
                HandshakeProducer handshakeProducer =
                        shc.handshakeProducers.remove(hs.id);
                if (handshakeProducer != null) {
                    handshakeProducer.produce(context, clientHello);
                }
            }
        }
    }

    /**
     * The "ClientHello" handshake message consumer for TLS 1.3.
     */
    private static final
            class T13ClientHelloConsumer implements HandshakeConsumer {
        // Prevent instantiation of this class.
        private T13ClientHelloConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The consuming happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;
            ClientHelloMessage clientHello = (ClientHelloMessage)message;

            // [RFC 8446] TLS 1.3 forbids renegotiation. If a server has
            // negotiated TLS 1.3 and receives a ClientHello at any other
            // time, it MUST terminate the connection with an
            // "unexpected_message" alert.
            if (shc.conContext.isNegotiated) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE,
                        "Received unexpected renegotiation handshake message");
            }

            // [RFC 8446] When session resumption is the primary use case of
            // PSKs, the most straightforward way to implement the PSK/cipher
            // suite matching requirements is to negotiate the cipher suite
            // first and then exclude any incompatible PSKs.
            //
            // Note: Please don't call handshakeHash.determine() here, in case
            // of need of calculating pre-shared key binders.
            shc.negotiatedCipherSuite = chooseCipherSuite(shc, clientHello);
            if (shc.negotiatedCipherSuite == null) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                        "no cipher suites in common");
            }

            // The client may send a dummy change_cipher_spec record
            // immediately after the first ClientHello.
            shc.conContext.consumers.putIfAbsent(
                    ContentType.CHANGE_CIPHER_SPEC.id,
                    ChangeCipherSpec.t13Consumer);

            // Is it a resumption?
            //
            // Check and launch the "psk_key_exchange_modes" and
            // "pre_shared_key" extensions first, which will reset the
            // resuming session, no matter the extensions present or not.
            shc.isResumption = true;
            SSLExtension[] extTypes = new SSLExtension[] {
                    SSLExtension.PSK_KEY_EXCHANGE_MODES,
                    SSLExtension.CH_PRE_SHARED_KEY
                };
            clientHello.extensions.consumeOnLoad(shc, extTypes);

            // Check and launch ClientHello extensions other than
            // "psk_key_exchange_modes", "pre_shared_key", "protocol_version"
            // and "key_share" extensions.
            //
            // These extensions may discard session resumption, or ask for
            // hello retry.
            extTypes = shc.sslConfig.getExclusiveExtensions(
                    SSLHandshake.CLIENT_HELLO,
                    Arrays.asList(
                            SSLExtension.PSK_KEY_EXCHANGE_MODES,
                            SSLExtension.CH_PRE_SHARED_KEY,
                            SSLExtension.CH_SUPPORTED_VERSIONS));
            clientHello.extensions.consumeOnLoad(shc, extTypes);

            shc.handshakeHash.determine(
                    shc.negotiatedProtocol, shc.negotiatedCipherSuite);

            if (!shc.handshakeProducers.isEmpty()) {
                // Should be HelloRetryRequest producer.
                goHelloRetryRequest(shc, clientHello);
            } else {
                goServerHello(shc, clientHello);
            }
        }

        // Choose the cipher suite for TLS 1.3 handshake.
        private static CipherSuite chooseCipherSuite(
                ServerHandshakeContext shc,
                ClientHelloMessage clientHello) {
            List<CipherSuite> preferred;
            List<CipherSuite> proposed;
            if (shc.sslConfig.preferLocalCipherSuites) {
                preferred = shc.activeCipherSuites;
                proposed = clientHello.cipherSuites;
            } else {
                preferred = clientHello.cipherSuites;
                proposed = shc.activeCipherSuites;
            }

            CipherSuite legacySuite = null;
            AlgorithmConstraints legacyConstraints =
                    ServerHandshakeContext.legacyAlgorithmConstraints;
            for (CipherSuite cs : preferred) {
                if (!HandshakeContext.isNegotiable(
                        proposed, shc.negotiatedProtocol, cs)) {
                    continue;
                }

                if ((legacySuite == null) &&
                        !legacyConstraints.permits(
                                EnumSet.of(CryptoPrimitive.KEY_AGREEMENT),
                                cs.name, null)) {
                    legacySuite = cs;
                    continue;
                }

                // The cipher suite has been negotiated.
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("use cipher suite " + cs.name);
                }
                return cs;
            }

            if (legacySuite != null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning(
                            "use legacy cipher suite " + legacySuite.name);
                }
                return legacySuite;
            }

            // no cipher suites in common
            return null;
        }

        private void goHelloRetryRequest(ServerHandshakeContext shc,
                ClientHelloMessage clientHello) throws IOException {
            HandshakeProducer handshakeProducer =
                    shc.handshakeProducers.remove(
                            SSLHandshake.HELLO_RETRY_REQUEST.id);
            if (handshakeProducer != null) {
                    handshakeProducer.produce(shc, clientHello);
            } else {
                // unlikely
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                    "No HelloRetryRequest producer: " + shc.handshakeProducers);
            }

            if (!shc.handshakeProducers.isEmpty()) {
                // unlikely, but please double check.
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                    "unknown handshake producers: " + shc.handshakeProducers);
            }
        }

        private void goServerHello(ServerHandshakeContext shc,
                ClientHelloMessage clientHello) throws IOException {
            //
            // validate
            //
            shc.clientHelloRandom = clientHello.clientRandom;

            //
            // update
            //
            if (!shc.conContext.isNegotiated) {
                shc.conContext.protocolVersion = shc.negotiatedProtocol;
                shc.conContext.outputRecord.setVersion(shc.negotiatedProtocol);
            }

            // update the responders
            //
            // Only ServerHello/HelloRetryRequest producer, which adds
            // more responders later.
            shc.handshakeProducers.put(SSLHandshake.SERVER_HELLO.id,
                SSLHandshake.SERVER_HELLO);

            SSLHandshake[] probableHandshakeMessages = new SSLHandshake[] {
                SSLHandshake.SERVER_HELLO,

                // full handshake messages
                SSLHandshake.ENCRYPTED_EXTENSIONS,
                SSLHandshake.CERTIFICATE_REQUEST,
                SSLHandshake.CERTIFICATE,
                SSLHandshake.CERTIFICATE_VERIFY,
                SSLHandshake.FINISHED
            };

            //
            // produce
            //
            for (SSLHandshake hs : probableHandshakeMessages) {
                HandshakeProducer handshakeProducer =
                        shc.handshakeProducers.remove(hs.id);
                if (handshakeProducer != null) {
                    handshakeProducer.produce(shc, clientHello);
                }
            }
        }
    }

    /**
     * The "ClientHello" handshake message consumer for DTLS 1.2 and
     * previous DTLS protocol versions.
     */
    private static final
            class D12ClientHelloConsumer implements HandshakeConsumer {
        // Prevent instantiation of this class.
        private D12ClientHelloConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The consuming happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;
            ClientHelloMessage clientHello = (ClientHelloMessage)message;

            //
            // validate
            //

            // Reject client initiated renegotiation?
            //
            // If server side should reject client-initiated renegotiation,
            // send an Alert.HANDSHAKE_FAILURE fatal alert, not a
            // no_renegotiation warning alert (no_renegotiation must be a
            // warning: RFC 2246).  no_renegotiation might seem more
            // natural at first, but warnings are not appropriate because
            // the sending party does not know how the receiving party
            // will behave.  This state must be treated as a fatal server
            // condition.
            //
            // This will not have any impact on server initiated renegotiation.
            if (shc.conContext.isNegotiated) {
                if (!shc.conContext.secureRenegotiation &&
                        !HandshakeContext.allowUnsafeRenegotiation) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                            "Unsafe renegotiation is not allowed");
                }

                if (ServerHandshakeContext.rejectClientInitiatedRenego &&
                        !shc.kickstartMessageDelivered) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                            "Client initiated renegotiation is not allowed");
                }
            }

            // Consume a Session Ticket Extension if it exists
            shc.isResumption = true;    // For the check of session ticket.
            SSLExtension[] ext = new SSLExtension[] {
                    SSLExtension.CH_SESSION_TICKET
            };
            clientHello.extensions.consumeOnLoad(shc, ext);
            if (shc.isResumption && shc.resumingSession == null) {
                // The SessionTicket extension is not available or cannot be
                // used for session resumption.  Check if the session ID can
                // be used instead.
                if (!clientHello.sessionId.isEmpty()) {
                    shc.resumingSession =
                        (SSLSessionImpl)shc.sslContext.serverCache.getSession(
                            clientHello.sessionId.getId());
                }
            }   // Otherwise, the SessionTicket extension is requested.

            // Can the session be resumed?
            if (shc.resumingSession == null ||
                    ((ServerSession)shc.resumingSession).cannotResume(shc)) {
                shc.isResumption = false;
                shc.resumingSession = null;
            }

            HelloCookieManager hcm =
                shc.sslContext.getHelloCookieManager(ProtocolVersion.DTLS10);
            if (!shc.isResumption &&
                !hcm.isCookieValid(shc, clientHello, clientHello.cookie)) {
                //
                // Perform cookie exchange for DTLS handshaking if no cookie
                // or the cookie is invalid in the ClientHello message.
                //
                // update the responders
                shc.handshakeProducers.put(
                        SSLHandshake.HELLO_VERIFY_REQUEST.id,
                        SSLHandshake.HELLO_VERIFY_REQUEST);

                //
                // produce response handshake message
                //
                SSLHandshake.HELLO_VERIFY_REQUEST.produce(context, clientHello);

                return;
            }

            // cache the client random number for further using
            shc.clientHelloRandom = clientHello.clientRandom;

            // Check and launch ClientHello extensions.
            SSLExtension[] extTypes = shc.sslConfig.getEnabledExtensions(
                    SSLHandshake.CLIENT_HELLO);
            clientHello.extensions.consumeOnLoad(shc, extTypes);

            //
            // update
            //
            if (!shc.conContext.isNegotiated) {
                shc.conContext.protocolVersion = shc.negotiatedProtocol;
                shc.conContext.outputRecord.setVersion(shc.negotiatedProtocol);
            }

            // update the responders
            //
            // Only need to ServerHello, which may add more responders later.
            shc.handshakeProducers.put(SSLHandshake.SERVER_HELLO.id,
                    SSLHandshake.SERVER_HELLO);

            //
            // produce
            //
            SSLHandshake[] probableHandshakeMessages = new SSLHandshake[] {
                SSLHandshake.SERVER_HELLO,

                // full handshake messages
                SSLHandshake.CERTIFICATE,
                SSLHandshake.CERTIFICATE_STATUS,
                SSLHandshake.SERVER_KEY_EXCHANGE,
                SSLHandshake.CERTIFICATE_REQUEST,
                SSLHandshake.SERVER_HELLO_DONE,

                // abbreviated handshake messages
                SSLHandshake.FINISHED
            };

            for (SSLHandshake hs : probableHandshakeMessages) {
                HandshakeProducer handshakeProducer =
                        shc.handshakeProducers.remove(hs.id);
                if (handshakeProducer != null) {
                    handshakeProducer.produce(context, clientHello);
                }
            }
        }
    }

    /**
     * The "ClientHello" handshake message consumer for DTLS 1.3.
     */
    private static final
            class D13ClientHelloConsumer implements HandshakeConsumer {
        // Prevent instantiation of this class.
        private D13ClientHelloConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    }
}
