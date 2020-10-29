/*
 * Copyright (c) 1996, 2020, Oracle and/or its affiliates. All rights reserved.
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

import sun.security.ssl.NewSessionTicket.SessionTicket;
import sun.security.ssl.NewSessionTicket.T13SessionTicket;
import sun.security.ssl.ServerNameExtension.CHServerNamesSpec.UnknownServerName;
import sun.security.util.Cache;
import sun.security.x509.X509CertImpl;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;

/**
 * Implements the SSL session interface, and exposes the session context
 * which is maintained by SSL servers.
 *
 * <P> Servers have the ability to manage the sessions associated with
 * their authentication context(s).  They can do this by enumerating the
 * IDs of the sessions which are cached, examining those sessions, and then
 * perhaps invalidating a given session so that it can't be used again.
 * If servers do not explicitly manage the cache, sessions will linger
 * until memory is low enough that the runtime environment purges cache
 * entries automatically to reclaim space.
 *
 * @author David Brownell
 */
abstract class SSLSessionImpl extends ExtendedSSLSession {
    // The context in which this session is bound.
    protected SSLSessionContextImpl         sessionContext;
    private final SSLContextImpl            sslContext;

    protected final ReentrantLock           sessionLock = new ReentrantLock();

    // The final states of the session.
    protected final ProtocolVersion         protocolVersion;

    // The
    protected final SessionId               sessionId;
    private final long                      creationTime;
    private final String                    host;
    private final int                       port;

    // could be final if not for serialization.
    SNIServerName                           serverNameIndication;
    final List<SNIServerName>               requestedServerNames;

    protected final String                  identificationProtocol;
    final boolean                           useExtendedMasterSecret;

    // Could be final if not for serialization.  Please don't update this field.
    protected final Collection<SignatureScheme> localSupportedSignAlgs;

    // Mutable states of the session.
    protected X509Certificate[]             peerCerts;
    protected CipherSuite                   cipherSuite;
    protected SecretKey                     masterSecret;   // TLS 1.2 and prior
    private long                            lastUsedTime = 0;
    private boolean                         invalidated;
    String                                  localPrivateKeyAlias;
    Collection<SignatureScheme>             peerSupportedSignAlgs;
    boolean                                 useDefaultPeerSignAlgs = false;

    int                                     negotiatedMaxFragLen = -1;
    final int                               maximumPacketSize;

    /**
     * Use large packet sizes now or follow RFC 2246 packet sizes (2^14)
     * until changed.
     * <p>
     * In the TLS specification (section 6.2.1, RFC2246), it is not
     * recommended that the plaintext has more than 2^14 bytes.
     * However, some TLS implementations violate the specification.
     * This is a workaround for interoperability with these stacks.
     * <p>
     * Application could accept large fragments up to 2^15 bytes by
     * setting the system property jsse.SSLEngine.acceptLargeFragments
     * to "true".
     */
    // Note: this System property is not respected in the implementation.
    // Maybe, the System property can be retired and large fragments are
    // not allowed any longer.
    // private static final boolean            acceptLargeFragments =
    private boolean                         acceptLargeFragments =
            Utilities.getBooleanProperty(
                    "jsse.SSLEngine.acceptLargeFragments", false);

    /*
     * Table of application-specific session data indexed by an application
     * key and the calling security context. This is important since
     * sessions can be shared across different protection domains.
     */
    private final ConcurrentHashMap<SecureKey, Object> boundValues;

    /*
     * Create a new non-rejoinable session, using the default (null)
     * cipher spec.
     */
    static SSLSessionImpl initialSessionFor(
            SSLContextImpl sslContext, SSLConfiguration sslConfig) {
        if (sslConfig.isClientMode) {
            return new ClientSession(sslContext);
        } else {
            return new ServerSession(sslContext);
        }
    }

    /*
     * Create a new non-rejoinable session, using the default (null)
     * cipher spec.
     */
    private SSLSessionImpl(SSLContextImpl sslContext) {
        this.sslContext = sslContext;
        this.protocolVersion = ProtocolVersion.NONE;
        this.cipherSuite = CipherSuite.C_NULL;
        this.sessionId = new SessionId(new byte[0]);
        this.host = null;
        this.port = -1;
        this.maximumPacketSize = 0;     // please reset it explicitly later.
        this.localSupportedSignAlgs = Collections.emptySet();
        this.peerSupportedSignAlgs = Collections.emptySet();
        this.serverNameIndication = null;
        this.requestedServerNames = Collections.emptyList();
        this.useExtendedMasterSecret = false;
        this.creationTime = System.currentTimeMillis();
        this.identificationProtocol = null;
        this.boundValues = new ConcurrentHashMap<>();
    }

    /*
     * Record a new session, using a given cipher spec, session ID,
     * and creation time.
     * Note: For the unmodifiable collections and lists we are creating new
     * collections as inputs to avoid potential deep nesting of
     * unmodifiable collections that can cause StackOverflowErrors
     * (see JDK-6323374).
     */
    private SSLSessionImpl(HandshakeContext hc,
                   CipherSuite cipherSuite, SessionId id, long creationTime) {
        this.sslContext = hc.sslContext;
        this.protocolVersion = hc.negotiatedProtocol;
        this.cipherSuite = cipherSuite;
        this.sessionId = id;
        this.host = hc.conContext.transport.getPeerHost();
        this.port = hc.conContext.transport.getPeerPort();
        this.maximumPacketSize = hc.sslConfig.maximumPacketSize;
        this.localSupportedSignAlgs = hc.localSupportedSignAlgs == null ?
                Collections.emptySet() :
                Collections.unmodifiableCollection(
                        new ArrayList<>(hc.localSupportedSignAlgs));
        this.peerSupportedSignAlgs = Collections.emptySet();
        this.serverNameIndication = hc.negotiatedServerName;
        this.requestedServerNames = List.copyOf(hc.getRequestedServerNames());

        if (hc.sslConfig.isClientMode) {
            this.useExtendedMasterSecret =
                    (hc.handshakeExtensions.get(
                            SSLExtension.CH_EXTENDED_MASTER_SECRET) != null) &&
                    (hc.handshakeExtensions.get(
                            SSLExtension.SH_EXTENDED_MASTER_SECRET) != null);
        } else {
            this.useExtendedMasterSecret =
                    (hc.handshakeExtensions.get(
                            SSLExtension.CH_EXTENDED_MASTER_SECRET) != null) &&
                    (!hc.negotiatedProtocol.useTLS13PlusSpec());
        }

        this.creationTime = creationTime;
        this.identificationProtocol = hc.sslConfig.identificationProtocol;
        this.boundValues = new ConcurrentHashMap<>();

        if (SSLLogger.isOn && SSLLogger.isOn("session")) {
            SSLLogger.finest("Session initialized:  " + this);
        }
    }

    private SSLSessionImpl(
            HandshakeContext hc,
            SessionEncoder proxy) throws CertificateException {
        this.sessionContext = null;
        this.sslContext = hc.sslContext;

        this.protocolVersion = proxy.protocolVersion;
        this.sessionId = new SessionId(proxy.sessionId);
        this.creationTime = proxy.creationTime;

        // Reset the peer host and port.
        this.host = hc.conContext.transport.getPeerHost();
        this.port = hc.conContext.transport.getPeerPort();

        if (proxy.sniType < 0 || proxy.sniType >= 0xFF ||   // one byte field
                proxy.sniEncoded == null || proxy.sniEncoded.length == 0) {
            this.serverNameIndication = null;
        } else if (proxy.sniType == StandardConstants.SNI_HOST_NAME) {
            this.serverNameIndication = new SNIHostName(proxy.sniEncoded);
        } else {
            this.serverNameIndication =
                    new UnknownServerName(proxy.sniType, proxy.sniEncoded);
        }

        this.requestedServerNames = new LinkedList<>();
        proxy.requestedServerNames.forEach((k, v) -> {
            if (k == StandardConstants.SNI_HOST_NAME) {
                this.requestedServerNames.add(new SNIHostName(v));
            } else {
                this.requestedServerNames.add(new UnknownServerName(k, v));
            }
        });

        this.identificationProtocol = proxy.identificationProtocol;
        this.useExtendedMasterSecret = proxy.useExtendedMasterSecret;

        if (proxy.peerCerts == null || proxy.peerCerts.length == 0) {
            this.peerCerts = null;
        } else {
            this.peerCerts = new X509Certificate[proxy.peerCerts.length];
            int i = 0;
            for (byte[] encodedCert : proxy.peerCerts) {
                this.peerCerts[i++] = new X509CertImpl(encodedCert);
            }
        }

        this.cipherSuite = proxy.cipherSuite;
        this.masterSecret = proxy.masterSecret;
        this.lastUsedTime = System.currentTimeMillis();
        this.invalidated = false;

        this.localPrivateKeyAlias = proxy.localPrivateKeyAlias;
        this.localSupportedSignAlgs = proxy.localSupportedSignAlgs;
        this.peerSupportedSignAlgs = proxy.peerSupportedSignAlgs;
        this.useDefaultPeerSignAlgs = proxy.useDefaultPeerSignAlgs;

        this.negotiatedMaxFragLen = proxy.negotiatedMaxFragLen;
        this.maximumPacketSize = proxy.maximumPacketSize;

        this.boundValues = new ConcurrentHashMap<>();
    }

    // Some situations we cannot provide a stateless ticket, but after it
    // has been negotiated
    boolean isStatelessable() {
        // If there is no masterSecret with TLS1.2 or under, do not resume.
        if (!protocolVersion.useTLS13PlusSpec() &&
                (masterSecret == null || masterSecret.getEncoded() == null)) {
            // The masterSecret may have not been negotiated if calling to
            // generate session ticket extension.
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.finest("No MasterSecret, cannot make stateless" +
                        " ticket");
            }

            return false;
        }

        if (boundValues != null && boundValues.size() > 0) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.finest("There are boundValues, cannot make" +
                        " stateless ticket");
            }

            return false;
        }

        return true;
    }

    // Used by TLS 1.2 and prior versions only.
    void setMasterSecret(SecretKey secret) {
        masterSecret = secret;
    }

    /**
     * Returns the master secret ... treat with extreme caution!
     */
    SecretKey getMasterSecret() {
        return masterSecret;
    }

    String getIdentificationProtocol() {
        return this.identificationProtocol;
    }

    void setPeerCertificates(X509Certificate[] peer) {
        if (peerCerts == null) {
            peerCerts = peer;
        }
    }

    void setLocalPrivateKey(X509Authentication.X509Possession possession) {
        this.localPrivateKeyAlias = possession.popPrivateKeyAlias;
    }

    void setPeerSupportedSignatureAlgorithms(
            Collection<SignatureScheme> signatureSchemes) {
        if (signatureSchemes == null ||  signatureSchemes.isEmpty()) {
            peerSupportedSignAlgs = Collections.emptySet();
        } else {
            peerSupportedSignAlgs = signatureSchemes;
        }
    }

    // TLS 1.2 only
    //
    // Per RFC 5246, If the client supports only the default hash
    // and signature algorithms, it MAY omit the
    // signature_algorithms extension.  If the client does not
    // support the default algorithms, or supports other hash
    // and signature algorithms (and it is willing to use them
    // for verifying messages sent by the server, i.e., server
    // certificates and server key exchange), it MUST send the
    // signature_algorithms extension, listing the algorithms it
    // is willing to accept.
    private static
        final ArrayList<SignatureScheme> defaultPeerSupportedSignAlgs =
            new ArrayList<>(Arrays.asList(SignatureScheme.RSA_PKCS1_SHA1,
                    SignatureScheme.DSA_SHA1,
                    SignatureScheme.ECDSA_SHA1));

    void setUseDefaultPeerSignAlgs() {
        useDefaultPeerSignAlgs = true;
        peerSupportedSignAlgs = defaultPeerSupportedSignAlgs;
    }

    // Returns the connection session.
    SSLSessionImpl finish() {
        if (useDefaultPeerSignAlgs) {
            peerSupportedSignAlgs = Collections.emptySet();
        }

        return this;
    }

    // Check if the session worthy of cache.
    boolean worthyOfCache() {
        return !invalidated;
    }

    @Override
    public boolean isValid() {
        sessionLock.lock();
        try {
            return !invalidated && isLocalAuthenticationValid();
        } finally {
            sessionLock.unlock();
        }
    }

    /**
     * Check if the authentication used when establishing this session
     * is still valid. Returns true if no authentication was used
     */
    private boolean isLocalAuthenticationValid() {
        if (localPrivateKeyAlias != null) {
            X509ExtendedKeyManager km = sslContext.getX509KeyManager();
            if (km != null) {       // unlikely
                PrivateKey localPrivateKey =
                        km.getPrivateKey(localPrivateKeyAlias);
                if (localPrivateKey != null) {
                    try {
                        // if the private key is no longer valid, getAlgorithm()
                        // should throw an exception
                        // (e.g. smart card has been removed from the reader)
                        localPrivateKey.getAlgorithm();
                    } catch (Exception e) {
                        invalidate();
                        return false;
                    }
                }
            }
        }

        return true;
    }

    /**
     * For server sessions, this returns the set of sessions which
     * are currently valid in this process.  For client sessions,
     * this returns null.
     */
    @Override
    public SSLSessionContext getSessionContext() {
        /*
         * An interim security policy until we can do something
         * more specific in 1.2. Only allow trusted code (code which
         * can set system properties) to get an
         * SSLSessionContext. This is to limit the ability of code to
         * look up specific sessions or enumerate over them. Otherwise,
         * code can only get session objects from successful SSL
         * connections which implies that they must have had permission
         * to make the network connection in the first place.
         */
        SecurityManager sm;
        if ((sm = System.getSecurityManager()) != null) {
            sm.checkPermission(new SSLPermission("getSSLSessionContext"));
        }

        return sessionContext;
    }

    SessionId getSessionId() {
        return sessionId;
    }

    /**
     * Returns the cipher spec in use on this session
     */
    CipherSuite getSuite() {
        return cipherSuite;
    }

    /**
     * Resets the cipher spec in use on this session
     */
    void setSuite(CipherSuite suite) {
        cipherSuite = suite;

        if (SSLLogger.isOn && SSLLogger.isOn("session")) {
            SSLLogger.finest("Negotiating session:  " + this);
        }
    }

    /**
     * Returns the name of the cipher suite in use on this session
     */
    @Override
    public String getCipherSuite() {
        return getSuite().name;
    }

    ProtocolVersion getProtocolVersion() {
        return protocolVersion;
    }

    /**
     * Returns the standard name of the protocol in use on this session
     */
    @Override
    public String getProtocol() {
        return getProtocolVersion().name;
    }

    /**
     * Return the cert chain presented by the peer in the
     * java.security.cert format.
     * Note: This method can be used only when using certificate-based
     * cipher suites; using it with non-certificate-based cipher suites
     * will throw an SSLPeerUnverifiedException.
     *
     * @return array of peer X.509 certs, with the peer's own cert
     * first in the chain, and with the "root" CA last.
     */
    @Override
    public java.security.cert.Certificate[] getPeerCertificates()
            throws SSLPeerUnverifiedException {
        //
        // clone to preserve integrity of session ... caller can't
        // change record of peer identity even by accident, much
        // less do it intentionally.
        //
        if (peerCerts == null) {
            throw new SSLPeerUnverifiedException("peer not authenticated");
        }

        // Certs are immutable objects, therefore we don't clone them.
        // But do need to clone the array, so that nothing is inserted
        // into peerCerts.
        return peerCerts.clone();
    }

    /**
     * Return the cert chain presented to the peer in the
     * java.security.cert format.
     * Note: This method is useful only when using certificate-based
     * cipher suites.
     *
     * @return array of peer X.509 certs, with the peer's own cert
     * first in the chain, and with the "root" CA last.
     */
    @Override
    public java.security.cert.Certificate[] getLocalCertificates() {
        if (localPrivateKeyAlias != null) {
            X509ExtendedKeyManager km = sslContext.getX509KeyManager();
            if (km != null) {       // unlikely
                return km.getCertificateChain(localPrivateKeyAlias);
            }
        }

        return null;
    }

    /**
     * Return the cert chain presented by the peer.
     * Note: This method can be used only when using certificate-based
     * cipher suites; using it with non-certificate-based cipher suites
     * will throw an SSLPeerUnverifiedException.
     *
     * @return array of peer X.509 certs, with the peer's own cert
     * first in the chain, and with the "root" CA last.
     */
    public X509Certificate[] getCertificateChain()
            throws SSLPeerUnverifiedException {
        /*
         * clone to preserve integrity of session ... caller can't
         * change record of peer identity even by accident, much
         * less do it intentionally.
         */
        if (peerCerts != null) {
            return peerCerts.clone();
        } else {
            throw new SSLPeerUnverifiedException("peer not authenticated");
        }
    }

    @Override
    public List<byte[]> getStatusResponses() {
            return Collections.emptyList();
    }

    /**
     * Returns the identity of the peer which was established as part of
     * defining the session.
     *
     * @return the peer's principal. Returns an X500Principal of the
     * end-entity certificate for X509-based cipher suites.
     * @throws SSLPeerUnverifiedException if the peer's identity has not
     *                                    been verified
     */
    @Override
    public Principal getPeerPrincipal()
            throws SSLPeerUnverifiedException {
        if (peerCerts == null) {
            throw new SSLPeerUnverifiedException("peer not authenticated");
        }
        return peerCerts[0].getSubjectX500Principal();
    }

    /**
     * Returns the principal that was sent to the peer during handshaking.
     *
     * @return the principal sent to the peer. Returns an X500Principal
     * of the end-entity certificate for X509-based cipher suites.
     * If no principal was sent, then null is returned.
     */
    @Override
    public Principal getLocalPrincipal() {
        if (localPrivateKeyAlias != null) {
            X509ExtendedKeyManager km = sslContext.getX509KeyManager();
            if (km != null) {       // unlikely
                X509Certificate[] localCerts =
                        km.getCertificateChain(localPrivateKeyAlias);
                if (localCerts != null && localCerts.length != 0) {
                    return localCerts[0].getSubjectX500Principal();
                }
            }
        }

        return null;
    }

    /**
     * Returns the time this session was created.
     */
    @Override
    public long getCreationTime() {
        return creationTime;
    }

    /**
     * Returns the last time this session was used to initialize
     * a connection.
     */
    @Override
    public long getLastAccessedTime() {
        return (lastUsedTime != 0) ? lastUsedTime : creationTime;
    }

    void setLastAccessedTime(long time) {
        lastUsedTime = time;
    }

    @Override
    public String getPeerHost() {
        return host;
    }

    /**
     * Need to provide the port info for caching sessions based on
     * host and port. Accessed by SSLSessionContextImpl
     */
    @Override
    public int getPeerPort() {
        return port;
    }

    // Used when binding with the session context.
    void setSessionContext(SSLSessionContextImpl ctx) {
        if (sessionContext == null) {
            sessionContext = ctx;
        }
    }

    /**
     * Invalidate a session.  Active connections may still exist, but
     * no connections will be able to rejoin this session.
     */
    @Override
    public void invalidate() {
        sessionLock.lock();
        try {
            if (sessionContext != null) {
                sessionContext.remove(this);
                sessionContext = null;
            }

            if (invalidated) {
                return;
            }
            invalidated = true;
            if (SSLLogger.isOn && SSLLogger.isOn("session")) {
                SSLLogger.finest("Invalidated session:  " + this);
            }
        } finally {
            sessionLock.unlock();
        }
    }

    /**
     * Assigns a session value.  Session change events are given if
     * appropriate, to any original value as well as the new value.
     */
    @Override
    @SuppressWarnings("deprecation")
    public void putValue(String key, Object value) {
        if ((key == null) || (value == null)) {
            throw new IllegalArgumentException("arguments can not be null");
        }

        SecureKey secureKey = new SecureKey(key);
        Object oldValue = boundValues.put(secureKey, value);

        if (oldValue instanceof SSLSessionBindingListener) {
            SSLSessionBindingEvent e;

            e = new SSLSessionBindingEvent(this, key);
            ((SSLSessionBindingListener) oldValue).valueUnbound(e);
        }
        if (value instanceof SSLSessionBindingListener) {
            SSLSessionBindingEvent e;

            e = new SSLSessionBindingEvent(this, key);
            ((SSLSessionBindingListener) value).valueBound(e);
        }
    }

    /**
     * Returns the specified session value.
     */
    @Override
    @SuppressWarnings("deprecation")
    public Object getValue(String key) {
        if (key == null) {
            throw new IllegalArgumentException("argument can not be null");
        }

        SecureKey secureKey = new SecureKey(key);
        return boundValues.get(secureKey);
    }


    /**
     * Removes the specified session value, delivering a session changed
     * event as appropriate.
     */
    @Override
    @SuppressWarnings("deprecation")
    public void removeValue(String key) {
        if (key == null) {
            throw new IllegalArgumentException("argument can not be null");
        }

        SecureKey secureKey = new SecureKey(key);
        Object value = boundValues.remove(secureKey);

        if (value instanceof SSLSessionBindingListener) {
            SSLSessionBindingEvent e;

            e = new SSLSessionBindingEvent(this, key);
            ((SSLSessionBindingListener) value).valueUnbound(e);
        }
    }

    /**
     * Lists the names of the session values.
     */
    @Override
    @SuppressWarnings("deprecation")
    public String[] getValueNames() {
        ArrayList<Object> v = new ArrayList<>();
        Object securityCtx = SecureKey.getCurrentSecurityContext();
        for (Enumeration<SecureKey> e = boundValues.keys();
             e.hasMoreElements(); ) {
            SecureKey key = e.nextElement();
            if (securityCtx.equals(key.getSecurityContext())) {
                v.add(key.getAppKey());
            }
        }

        return v.toArray(new String[0]);
    }

    /**
     * Expand the buffer size of both SSL/TLS network packet and
     * application data.
     */
    protected void expandBufferSizes() {
        sessionLock.lock();
        try {
            acceptLargeFragments = true;
        } finally {
            sessionLock.unlock();
        }
    }

    /**
     * Gets the current size of the largest SSL/TLS packet that is expected
     * when using this session.
     */
    @Override
    public int getPacketBufferSize() {
        sessionLock.lock();
        try {
            // Use the bigger packet size calculated from maximumPacketSize
            // and negotiatedMaxFragLen.
            int packetSize = 0;
            if (negotiatedMaxFragLen > 0) {
                packetSize = cipherSuite.calculatePacketSize(
                        negotiatedMaxFragLen, protocolVersion,
                        protocolVersion.isDTLS);
            }

            if (maximumPacketSize > 0) {
                return Math.max(maximumPacketSize, packetSize);
            }

            if (packetSize != 0) {
                return packetSize;
            }

            if (protocolVersion.isDTLS) {
                return DTLSRecord.maxRecordSize;
            } else {
                return acceptLargeFragments ?
                        SSLRecord.maxLargeRecordSize : SSLRecord.maxRecordSize;
            }
        } finally {
            sessionLock.unlock();
        }
    }

    /**
     * Gets the current size of the largest application data that is
     * expected when using this session.
     */
    @Override
    public int getApplicationBufferSize() {
        sessionLock.lock();
        try {
            // Use the bigger fragment size calculated from maximumPacketSize
            // and negotiatedMaxFragLen.
            int fragmentSize = 0;
            if (maximumPacketSize > 0) {
                fragmentSize = cipherSuite.calculateFragSize(
                        maximumPacketSize, protocolVersion,
                        protocolVersion.isDTLS);
            }

            if (negotiatedMaxFragLen > 0) {
                return Math.max(negotiatedMaxFragLen, fragmentSize);
            }

            if (fragmentSize != 0) {
                return fragmentSize;
            }

            if (protocolVersion.isDTLS) {
                return Record.maxDataSize;
            } else {
                int maxPacketSize = acceptLargeFragments ?
                        SSLRecord.maxLargeRecordSize : SSLRecord.maxRecordSize;
                return (maxPacketSize - SSLRecord.headerSize);
            }
        } finally {
            sessionLock.unlock();
        }
    }

    /**
     * Sets the negotiated maximum fragment length, as specified by the
     * max_fragment_length ClientHello extension in RFC 6066.
     *
     * @param negotiatedMaxFragLen the negotiated maximum fragment length,
     *        or {@code -1} if no such length has been negotiated.
     */
    void setNegotiatedMaxFragSize(int negotiatedMaxFragLen) {
        sessionLock.lock();
        try {
            this.negotiatedMaxFragLen = negotiatedMaxFragLen;
        } finally {
            sessionLock.unlock();
        }
    }

    /**
     * Get the negotiated maximum fragment length, as specified by the
     * max_fragment_length ClientHello extension in RFC 6066.
     *
     * @return the negotiated maximum fragment length, or {@code -1} if
     * no such length has been negotiated.
     */
    int getNegotiatedMaxFragSize() {
        sessionLock.lock();
        try {
            return negotiatedMaxFragLen;
        } finally {
            sessionLock.unlock();
        }
    }

    /**
     * Gets an array of supported signature algorithm names that the local
     * side is willing to verify.
     */
    @Override
    public String[] getLocalSupportedSignatureAlgorithms() {
        return SignatureScheme.getAlgorithmNames(localSupportedSignAlgs);
    }

    /**
     * Gets an array of supported signature algorithms that the peer is
     * able to verify.
     */
    @Override
    public String[] getPeerSupportedSignatureAlgorithms() {
        return SignatureScheme.getAlgorithmNames(peerSupportedSignAlgs);
    }

    /**
     * Obtains a <code>List</code> containing all {@link SNIServerName}s
     * of the requested Server Name Indication (SNI) extension.
     */
    @Override
    public List<SNIServerName> getRequestedServerNames() {
        return requestedServerNames;
    }

    /**
     * Returns a string representation of this SSL session
     */
    @Override
    public String toString() {
        return "Session(" + creationTime + "|" + getCipherSuite() + "|" +
                sessionId + "|" + (invalidated ? "invalid" : "valid") + ")";
    }

    /**
     * This "struct" class serves as a Hash Key that combines an
     * application-specific key and a security context.
     */
    private static class SecureKey {
        private static final Object nullObject = new Object();
        private final Object appKey;
        private final Object securityCtx;

        static Object getCurrentSecurityContext() {
            SecurityManager sm = System.getSecurityManager();
            Object context = null;

            if (sm != null)
                context = sm.getSecurityContext();
            if (context == null)
                context = nullObject;
            return context;
        }

        SecureKey(Object key) {
            this.appKey = key;
            this.securityCtx = getCurrentSecurityContext();
        }

        Object getAppKey() {
            return appKey;
        }

        Object getSecurityContext() {
            return securityCtx;
        }

        @Override
        public int hashCode() {
            return appKey.hashCode() ^ securityCtx.hashCode();
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof SecureKey
                    && ((SecureKey) o).appKey.equals(appKey)
                    && ((SecureKey) o).securityCtx.equals(securityCtx);
        }
    }

    //
    // The client session implementation.
    //
    static class ClientSession extends SSLSessionImpl {
        List<byte[]> statusResponses;

        final SessionId clientHelloId;
        final Queue<SessionTicket> sessionTickets = new LinkedList<>();

        private ClientSession(SSLContextImpl sslContext) {
            super(sslContext);
            this.clientHelloId = new SessionId(new byte[0]);
        }

        private ClientSession(HandshakeContext hc,
              CipherSuite cipherSuite, SessionId sessionId,
              SessionId clientHelloId, long creationTime) {
            super(hc, cipherSuite, sessionId, creationTime);
            this.clientHelloId = clientHelloId;
        }

        static ClientSession createSession(HandshakeContext hc,
               CipherSuite cipherSuite, SessionId sessionId,
               SessionId clientHelloId) {
            if (sessionId == null || sessionId.isEmpty()) {
                sessionId = new SessionId(hc.sslContext.getSecureRandom());
            }

            return new ClientSession(hc, cipherSuite,
                    sessionId, clientHelloId,
                    System.currentTimeMillis());
        }

        // Provide status response data obtained during the SSL handshake.
        void setStatusResponses(List<byte[]> responses) {
            if (responses != null && !responses.isEmpty()) {
                statusResponses = responses;
            } else {
                statusResponses = Collections.emptyList();
            }
        }

        @Override
        public List<byte[]> getStatusResponses() {
            if (statusResponses == null || statusResponses.isEmpty()) {
                return Collections.emptyList();
            } else {
                // Clone both the list and the contents
                List<byte[]> responses =
                        new ArrayList<>(statusResponses.size());
                for (byte[] respBytes : statusResponses) {
                    responses.add(respBytes.clone());
                }

                return Collections.unmodifiableList(responses);
            }
        }


        // Used to merge session tickets of the replaced session in the cache.
        void mergeTickets(ClientSession replacedSession) {
            if (!replacedSession.sessionTickets.isEmpty()) {
                sessionTickets.addAll(replacedSession.sessionTickets);
            }
        }

        @Override
        public boolean isValid() {
            sessionLock.lock();
            try {
                if (!super.isValid()) {
                    return false;
                } else if (!sessionTickets.isEmpty()) {
                    return true;
                } else if (!this.protocolVersion.useTLS13PlusSpec()) {
                    return sessionId != null && !sessionId.isEmpty();
                }
            } finally {
                sessionLock.unlock();
            }

            // Note: For TLS 1.3, the NewSessionTicket post-handshake message
            // may have not been transmitted, while this method get called.
            return false;
        }

        // Note: the returned value is not cloned for performance, please
        // don't update the returned byte array!!!
        //
        // Return empty byte array if no cached session ticket, or the
        // cached session tickets have expired.
        SessionTicket getSessionTicket() {
            sessionLock.lock();
            try {
                if (this.protocolVersion.useTLS13PlusSpec()) {
                    return getT13SessionTicket();
                } else {        // TLS 1.2 and prior versions
                    return getT12SessionTicket();
                }
            } finally {
                sessionLock.unlock();
            }
        }

        private SessionTicket getT13SessionTicket() {
            // Don't reuse session ticket for TLS 1.3.
            for (SessionTicket sessionTicket = sessionTickets.poll();
                 sessionTicket != null;
                 sessionTicket = sessionTickets.poll()) {
                if (!(sessionTicket instanceof T13SessionTicket)) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.finest(
                                "Removed an unexpected session ticket");
                    }

                    continue;
                }

                if (sessionTicket.expires >= System.currentTimeMillis()) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.finest("Got a TLS 1.3+ session ticket");
                    }

                    return sessionTicket;
                }

                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest("Removed an expired session ticket");
                }
            }

            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.finest("Found no cached TLS 1.3+ session ticket");
            }

            return null;
        }

        private SessionTicket getT12SessionTicket() {
            // The session ticket for TLS 1.2 and prior versions could
            // be reused if competition happens.
            SessionTicket sessionTicket = sessionTickets.peek();
            if (sessionTicket instanceof T13SessionTicket) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest("Not a TLS 1.2- session ticket");
                }

                return null;
            }

            if (sessionTicket != null &&
                    sessionTicket.expires >= System.currentTimeMillis()) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest("Got a TLS 1.2- session ticket");
                }
                return sessionTicket;
            }

            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.finest("Found no cached TLS 1.2- session ticket");
            }

            return null;
        }

        void putSessionTicket(SessionTicket sessionTicket) {
            sessionLock.lock();
            try {
                // Note: TLS 1.3 could have 1+ session ticket, while TLS 1.2
                // and prior versions will only use the current session ticket.
                if (!this.protocolVersion.useTLS13PlusSpec()) {
                    // Remove the previous session tickets.
                    sessionTickets.clear();
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.finest(
                                "Cleared old cached session tickets");
                    }

                    sessionTickets.add(sessionTicket);
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.finest("Cached a TLS 1.2- session ticket");
                    }
                } else {
                    sessionTickets.add(sessionTicket);
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.finest("Cached a TLS 1.3+ session ticket");
                    }
                }
            } finally {
                sessionLock.unlock();
            }
        }

        // Returns the ID for this session.  The ID is fixed for the
        // duration of the session; neither it, nor its value, changes.
        @Override
        public byte[] getId() {
            return sessionId.getId();
        }

        @Override
        public int hashCode() {
            return sessionId.hashCode();
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) {
                return true;
            }

            if (obj instanceof ClientSession) {
                return this.clientHelloId == ((ClientSession)obj).clientHelloId;
            }

            return false;
        }
    }

    //
    // The server session implementation.
    //
    static class ServerSession extends SSLSessionImpl {
        private static final int DEFAULT_TICKET_NUMBER = 2;
        final Cache<Long, T13SessionTicket> statefulTicketCache;

        private ServerSession(SSLContextImpl sslContext) {
            super(sslContext);
            statefulTicketCache = null;
        }

        private ServerSession(HandshakeContext hc,
                CipherSuite cipherSuite, SessionId id, long creationTime) {
            super(hc, cipherSuite, id, creationTime);
            statefulTicketCache = Cache.newSoftMemoryCache(
                    DEFAULT_TICKET_NUMBER,
                    hc.sslContext.serverCache.getSessionTimeout());
        }

        private ServerSession(
                HandshakeContext hc,
                SessionEncoder proxy) throws CertificateException {
            super(hc, proxy);
            statefulTicketCache = Cache.newSoftMemoryCache(
                    DEFAULT_TICKET_NUMBER,
                    hc.sslContext.serverCache.getSessionTimeout());
        }

        static ServerSession createSession(HandshakeContext hc) {
            return new ServerSession(hc, CipherSuite.C_NULL,
                    new SessionId(hc.sslContext.getSecureRandom()),
                    System.currentTimeMillis());
        }

        // Check if the session worthy of cache.
        @Override
        boolean worthyOfCache() {
            return super.worthyOfCache() &&
                    sessionId != null && !sessionId.isEmpty();
        }

        // Check if the session could be resumed or rejoined, used by server
        // handshake.
        boolean cannotResume(ServerHandshakeContext shc) {
            if (!isValid()) {
                return true;
            }

            // Check protocol version
            if (protocolVersion != shc.negotiatedProtocol) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                    SSLLogger.finest(
                            "Can't resume, incorrect protocol version");
                }

                return true;
            }

            // Check cipher suite
            if (shc.negotiatedCipherSuite != null) {
                if (cipherSuite != shc.negotiatedCipherSuite) {
                    if (SSLLogger.isOn &&
                            SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest(
                                "Can't resume, incorrect cipher suite");
                    }

                    return true;
                }
            } else if (!shc.activeCipherSuites.contains(cipherSuite)){
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                    SSLLogger.finest("Can't resume, inactive cipher suite");
                }

                return true;
            }

            // Validate the required client authentication.
            if ((shc.sslConfig.clientAuthType ==
                    ClientAuthType.CLIENT_AUTH_REQUIRED)) {
                if (peerCerts == null) {
                    if (SSLLogger.isOn &&
                            SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest(
                            "Can't resume, client authentication is required");
                    }

                    return true;
                }

                // Make sure the list of supported signature algorithms matches
                if (shc.localSupportedSignAlgs == null) {
                    shc.localSupportedSignAlgs =
                        SignatureScheme.getSupportedAlgorithms(
                                shc.sslConfig,
                                shc.algorithmConstraints, shc.activeProtocols);
                }
                if (!shc.localSupportedSignAlgs
                        .containsAll(localSupportedSignAlgs)) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine(
                                "Can't resume. Session uses different " +
                                "signature algorithms");
                    }

                    return true;
                }
            }

            // ensure that the endpoint identification algorithm matches the
            // one in the session
            String identityAlg = shc.sslConfig.identificationProtocol;
            if (identityAlg != null) {
                if (!identityAlg.equalsIgnoreCase(identificationProtocol)) {
                    if (SSLLogger.isOn &&
                            SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest(
                                "Can't resume, endpoint id algorithm does " +
                                "not match, requested: " + identityAlg +
                                ", cached: " + identificationProtocol);
                    }

                    return true;
                }
            }

            return false;
        }

        T13SessionTicket getStatefulSessionTicket(long ticketId) {
            return statefulTicketCache.get(ticketId);
        }

        void putStatefulSessionTicket(long ticketId,
                                      T13SessionTicket sessionTicket) {
            statefulTicketCache.put(ticketId, sessionTicket);
        }

        byte[] encodeT12StatelessTicket() {
            return encodeStatelessTicket(null);
        }

        byte[] encodeT13StatelessTicket(
                SecretKey sharedSecret) {
            return encodeStatelessTicket(sharedSecret);
        }

        private byte[] encodeStatelessTicket(SecretKey sharedSecret) {
            try {
                return (new SessionEncoder(this, sharedSecret)).encode();
            } catch (IOException | CertificateEncodingException ioe) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning(
                            "Unable encode session to ticket", ioe);
                }

                return new byte[0];
            }
        }

        static ServerSession decodeT12StatelessTicket(
                HandshakeContext hc, byte[] ticket) {
            try {
                return new ServerSession(hc,
                        SessionEncoder.decode(ByteBuffer.wrap(ticket)));
            } catch (IOException | CertificateException ioe) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning(
                            "Cannot decode session from ticket", ioe);
                }

                return null;
            }
        }

        static Map.Entry<SecretKey, ServerSession> decodeT13StatelessTicket(
                HandshakeContext hc, byte[] ticket) {
            try {
                ServerSession session = new ServerSession(hc,
                        SessionEncoder.decode(ByteBuffer.wrap(ticket)));
                SecretKey sharedSecret = session.masterSecret;
                session.masterSecret = null;

                return new AbstractMap.SimpleEntry<>(sharedSecret, session);
            } catch (IOException |
                    CertificateException ioe) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning(
                            "Cannot decode session from ticket", ioe);
                }

                return null;
            }
        }

        // Returns the ID for this session.  The ID is fixed for the
        // duration of the session; neither it, nor its value, changes.
        @Override
        public byte[] getId() {
            return sessionId.getId();
        }

        @Override
        public int hashCode() {
            return sessionId.hashCode();
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) {
                return true;
            }

            if (obj instanceof ServerSession) {
                return (sessionId != null) &&
                        (sessionId.equals(((ServerSession)obj).sessionId));
            }

            return false;
        }
    }

    private static class SessionEncoder {
        // Copy of session status.
        //
        // Note: The default serialization should be able to use these fields.
        private final ProtocolVersion               protocolVersion;
        private final byte[]                        sessionId;
        private final long                          creationTime;
        private final int                           sniType;
        private final byte[]                        sniEncoded;
        private final HashMap<Integer, byte[]>      requestedServerNames;
        private final String                        identificationProtocol;
        private final boolean                       useExtendedMasterSecret;
        private final byte[][]                      peerCerts;
        private final CipherSuite                   cipherSuite;
        private final SecretKey                     masterSecret;
        private final String                        localPrivateKeyAlias;
        private final Collection<SignatureScheme>   localSupportedSignAlgs;
        private final Collection<SignatureScheme>   peerSupportedSignAlgs;
        private final boolean                       useDefaultPeerSignAlgs;
        private final int                           negotiatedMaxFragLen;
        private final int                           maximumPacketSize;

        private SessionEncoder(
                final ProtocolVersion               protocolVersion,
                final byte[] sessionId,
                final long                          creationTime,
                final int                           sniType,
                final byte[]                        sniEncoded,
                final HashMap<Integer, byte[]>      requestedServerNames,
                final String                        identificationProtocol,
                final boolean                       useExtendedMasterSecret,
                final byte[][]                      peerCerts,
                final CipherSuite                   cipherSuite,
                final SecretKey                     masterSecret,
                final String                        localPrivateKeyAlias,
                final Collection<SignatureScheme>   localSupportedSignAlgs,
                final Collection<SignatureScheme>   peerSupportedSignAlgs,
                final boolean                       useDefaultPeerSignAlgs,
                final int                           negotiatedMaxFragLen,
                final int                           maximumPacketSize
        ) {
            this.protocolVersion = protocolVersion;
            this.sessionId = sessionId;
            this.creationTime = creationTime;
            this.sniType = sniType;
            this.sniEncoded = sniEncoded;
            this.requestedServerNames = requestedServerNames;
            this.identificationProtocol = identificationProtocol;
            this.useExtendedMasterSecret = useExtendedMasterSecret;
            this.peerCerts = peerCerts;
            this.cipherSuite = cipherSuite;
            this.masterSecret = masterSecret;
            this.localPrivateKeyAlias = localPrivateKeyAlias;
            this.localSupportedSignAlgs = localSupportedSignAlgs;
            this.peerSupportedSignAlgs = peerSupportedSignAlgs;
            this.useDefaultPeerSignAlgs = useDefaultPeerSignAlgs;
            this.negotiatedMaxFragLen = negotiatedMaxFragLen;
            this.maximumPacketSize = maximumPacketSize;
        }

        private SessionEncoder(
                ServerSession session,
                SecretKey shareSecret) throws CertificateEncodingException {
            this.protocolVersion = session.protocolVersion;

            if (session.sessionId != null) {
                this.sessionId = session.sessionId.getId();
            } else {
                this.sessionId = null;
            }

            this.creationTime = session.getCreationTime();
            if (session.serverNameIndication != null) {
                this.sniType = session.serverNameIndication.getType();
                this.sniEncoded = session.serverNameIndication.getEncoded();
            } else {
                this.sniType = -1;
                this.sniEncoded = null;
            }

            this.requestedServerNames = new HashMap<>(
                    session.requestedServerNames.size());
            for (SNIServerName sni : session.requestedServerNames) {
                requestedServerNames.put(sni.getType(), sni.getEncoded());
            }

            this.identificationProtocol = session.identificationProtocol;
            this.useExtendedMasterSecret = session.useExtendedMasterSecret;
            if (session.peerCerts != null) {
                this.peerCerts = new byte[session.peerCerts.length][];
                for (int i = 0; i < session.peerCerts.length; i++) {
                    this.peerCerts[i] = session.peerCerts[i].getEncoded();
                }
            } else {
                this.peerCerts = null;
            }

            this.cipherSuite = session.cipherSuite;
            if (protocolVersion.useTLS13PlusSpec()) {
                this.masterSecret = shareSecret;
            } else {
                this.masterSecret = session.masterSecret;
            }

            this.localPrivateKeyAlias = session.localPrivateKeyAlias;
            this.localSupportedSignAlgs = session.localSupportedSignAlgs;
            this.peerSupportedSignAlgs = session.peerSupportedSignAlgs;
            this.useDefaultPeerSignAlgs = session.useDefaultPeerSignAlgs;

            this.negotiatedMaxFragLen = session.negotiatedMaxFragLen;
            this.maximumPacketSize = session.maximumPacketSize;
        }

        private byte[] encode() throws IOException {
            HandshakeOutStream hos = new HandshakeOutStream(null);

            hos.putInt16(protocolVersion.id);
            hos.putBytes8(sessionId);
            hos.putInt64(creationTime);
            hos.putInt8(sniType);
            hos.putBytes16(sniEncoded);

            int size = 0;
            for (Map.Entry<Integer, byte[]> sni :
                    requestedServerNames.entrySet()) {
                size += sni.getValue().length + 3;
            }
            hos.putInt16(size);
            for (Map.Entry<Integer, byte[]> sni :
                    requestedServerNames.entrySet()) {
                hos.putInt8(sni.getKey());
                hos.putBytes16(sni.getValue());
            }

            if (identificationProtocol != null) {
                hos.putBytes8(identificationProtocol.getBytes());
            } else {
                hos.putBytes8(new byte[0]);
            }
            hos.putInt8(useExtendedMasterSecret ? (byte)1 : (byte)0);

            if (peerCerts == null) {
                hos.putInt24(0);
            } else {
                size = 0;
                for (byte[] cert : peerCerts) {
                    size += cert.length + 3;
                }

                hos.putInt24(size);
                for (byte[] cert : peerCerts) {
                    hos.putBytes24(cert);
                }
            }

            hos.putInt16(cipherSuite.id);

            byte[] encodedKey = masterSecret.getEncoded();
            hos.putBytes16(encodedKey);

            if (localPrivateKeyAlias != null) {
                hos.putBytes8(localPrivateKeyAlias.getBytes());
            } else {
                hos.putBytes8(new byte[0]);
            }

            hos.putInt16(localSupportedSignAlgs.size() * 2);
            for (SignatureScheme ss : localSupportedSignAlgs) {
                hos.putInt16(ss.id);
            }

            hos.putInt16(peerSupportedSignAlgs.size() * 2);
            for (SignatureScheme ss : peerSupportedSignAlgs) {
                hos.putInt16(ss.id);
            }

            hos.putInt8(useDefaultPeerSignAlgs ? (byte)1 : (byte)0);

            hos.putInt16(negotiatedMaxFragLen);
            hos.putInt16(maximumPacketSize);

            return hos.toByteArray();
        }

        private static SessionEncoder decode(ByteBuffer m) throws IOException {
            ProtocolVersion protocolVersion =
                    ProtocolVersion.valueOf(Record.getInt16(m));
            byte[] sessionId = Record.getBytes8(m);
            long creationTime = Record.getInt64(m);
            int sniType = Record.getInt8(m);
            byte[] sniEncoded = Record.getBytes16(m);

            int size = Record.getInt16(m);
            HashMap<Integer, byte[]> requestedServerNames = new HashMap<>();
            while (size > 0) {
                int nameType = Record.getInt8(m);
                byte[] sniName = Record.getBytes16(m);
                size -= 3 + sniName.length;
                requestedServerNames.put(nameType, sniName);
            }

            String identificationProtocol = new String(Record.getBytes8(m));
            boolean useExtendedMasterSecret = Record.getInt8(m) != 0;

            size = Record.getInt24(m);
            ArrayList<byte[]> certs = new ArrayList<>();
            while (size > 0) {
                byte[] cert = Record.getBytes24(m);
                size -= 3 + cert.length;
                certs.add(cert);
            }
            byte[][] peerCerts = certs.toArray(new byte[0][]);

            CipherSuite cipherSuite = CipherSuite.valueOf(Record.getInt16(m));

            SecretKey masterSecret;
            if (protocolVersion != null && protocolVersion.useTLS13PlusSpec()) {
                masterSecret =
                    new SecretKeySpec(Record.getBytes16(m), "TlsResumption");
            } else {
                masterSecret =
                    new SecretKeySpec(Record.getBytes16(m), "TlsMasterSecret");
            }
            String localPrivateKeyAlias = new String(Record.getBytes8(m));


            size = Record.getInt16(m);
            List<SignatureScheme> localSupportedSignAlgs = new LinkedList<>();
            while (size > 0) {
                size -= 2;
                localSupportedSignAlgs.add(
                        SignatureScheme.valueOf(Record.getInt16(m)));
            }

            size = Record.getInt16(m);
            List<SignatureScheme> peerSupportedSignAlgs = new LinkedList<>();
            while (size > 0) {
                size -= 2;
                peerSupportedSignAlgs.add(
                        SignatureScheme.valueOf(Record.getInt16(m)));
            }

            boolean useDefaultPeerSignAlgs = Record.getInt8(m) != 0;

            int negotiatedMaxFragLen = Record.getInt16(m);
            if (negotiatedMaxFragLen > Short.MAX_VALUE) {
                negotiatedMaxFragLen = -1;
            }
            int maximumPacketSize = Record.getInt16(m);
            if(maximumPacketSize > Short.MAX_VALUE) {
                maximumPacketSize = -1;
            }

            return new SessionEncoder(protocolVersion,
                    sessionId, creationTime, sniType, sniEncoded,
                    requestedServerNames, identificationProtocol,
                    useExtendedMasterSecret, peerCerts,
                    cipherSuite, masterSecret, localPrivateKeyAlias,
                    localSupportedSignAlgs, peerSupportedSignAlgs,
                    useDefaultPeerSignAlgs,
                    negotiatedMaxFragLen, maximumPacketSize);
        }
    }
}
