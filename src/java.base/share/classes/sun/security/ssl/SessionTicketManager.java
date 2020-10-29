/*
 * Copyright (c) 2020, Oracle and/or its affiliates. All rights reserved.
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

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.X509KeyManager;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.*;
import java.util.concurrent.locks.ReentrantLock;

/**
 * TLS 1.3 stateless session ticket manager.
 */
final class SessionTicketManager
        implements Flow.Subscriber<SessionTicketManager.SecretRecord> {
    static final TicketKeyScheme DEFAULT_TICKET_KEY_SCHEME =
            TicketKeyScheme.AES_256_GCM_SHA512;

    private final SecureRandom secureRandom;
    private final TicketScheme ticketScheme;

    SessionTicketManager(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
        this.ticketScheme = new TicketScheme();
    }

    @Override
    public void onSubscribe(Flow.Subscription subscription) {
        ticketScheme.subscription = subscription;
        subscription.request(1);
    }

    @Override
    public void onNext(SecretRecord secretRecord) {
        if (ticketScheme.subscription == null) {
            return;
        }

        if (secretRecord != null) {
            if (SSLLogger.isOn && SSLLogger.isOn("session")) {
                SSLLogger.fine("Rotate the session ticket protection secret");
            }
            this.ticketScheme.outerRotate(secretRecord);
        } else {
            if (SSLLogger.isOn && SSLLogger.isOn("session")) {
                SSLLogger.severe("A null secret was published");
            }
        }
    }

    @Override
    public void onError(Throwable throwable) {
        ticketScheme.subscription = null;
        if (SSLLogger.isOn && SSLLogger.isOn("session")) {
            SSLLogger.severe("The publisher run into problem", throwable);
        }
    }

    @Override
    public void onComplete() {
        ticketScheme.subscription = null;
        if (SSLLogger.isOn && SSLLogger.isOn("session")) {
            SSLLogger.severe("The publisher has completed");
        }
    }

    byte[] encodeTicket(byte[] plaintextTicket) {
        return ticketScheme.encodeTicket(secureRandom, plaintextTicket);
    }

    byte[] decodeTicket(ByteBuffer ticketBuffer) {
        byte[] ticketBytes = new byte[ticketBuffer.remaining()];
        ticketBuffer.get(ticketBytes);

        return decodeTicket(ticketBytes);
    }

    byte[] decodeTicket(byte[] cipheredTicket) {
        return ticketScheme.decodeTicket(secureRandom, cipheredTicket);
    }

    protected static final class SecretRecord {
        private final long notBeforeMillis;
        private final long notAfterMillis;
        private final SecretKey secretKey;
        private final byte[] validUntilMillis;

        private SecretRecord(long notBeforeMillis,
                             long notAfterMillis, SecretKey secretKey) {
            this.notBeforeMillis = notBeforeMillis;
            this.notAfterMillis = notAfterMillis;
            this.secretKey = secretKey;

            this.validUntilMillis = Utilities.toByteArray(notAfterMillis);
        }
    }

    private static final class TicketScheme {
        private volatile Flow.Subscription subscription;

        private volatile SecretRecord legacySecret;
        private volatile SecretRecord ondutySecret;

        protected final ReentrantLock rotationLock = new ReentrantLock();

        private TicketScheme() {
            this.legacySecret = null;
            this.ondutySecret = null;
        }

        private byte[] encodeTicket(SecureRandom secureRandom,
                byte[] plaintextTicket) {
            // Rotate the secret record if timeout.
            rotateIfOndutyRecordTimeout();

            // Just use the onduty secret key, no synchronization necessary.
            //
            // The key rotation may be in progress, but it is fine to use the
            // current onduty secret key.
            //
            // Note: please don't use the class variable directly. Get
            // a reference firstly.
            SecretRecord inUseRecord = ondutySecret;
            if (ondutySecret != null) {
                return DEFAULT_TICKET_KEY_SCHEME.encrypt(
                        inUseRecord, secureRandom, plaintextTicket);
            }

            return null;
        }

        private byte[] decodeTicket(
                SecureRandom secureRandom, byte[] cipheredTicket) {
            // Is it a valid session ticket?
            if (cipheredTicket.length < Long.BYTES) {
                if (SSLLogger.isOn && SSLLogger.isOn("session")) {
                    SSLLogger.warning(
                            "Invalid session ticket: no sufficient data");
                }

                return null;
            }

            // Rotate the secret record if timeout.
            rotateIfOndutyRecordTimeout();

            // Note: please don't use the class variable directly. Get
            // a reference firstly.
            //
            // Check the onduty secret record.
            SecretRecord inUseRecord = ondutySecret;
            long validUntilMillis = Utilities.toLong(cipheredTicket);
            if (validUntilMillis > inUseRecord.notAfterMillis) {
                if (SSLLogger.isOn && SSLLogger.isOn("session")) {
                    SSLLogger.warning(
                            "Invalid session ticket: a future validity");
                }

                return null;
            }

            if (validUntilMillis > inUseRecord.notBeforeMillis) {
                return DEFAULT_TICKET_KEY_SCHEME.decrypt(
                        inUseRecord, secureRandom, cipheredTicket,
                        Long.BYTES, cipheredTicket.length - Long.BYTES);
            }

            // Check the legacy secret record.
            inUseRecord = legacySecret;
            if (validUntilMillis <= inUseRecord.notBeforeMillis) {
                if (SSLLogger.isOn && SSLLogger.isOn("session")) {
                    SSLLogger.warning(
                            "Invalid session ticket: a retired validity");
                }

                return null;
            }

            if (validUntilMillis <= inUseRecord.notAfterMillis) {
                return DEFAULT_TICKET_KEY_SCHEME.decrypt(
                        inUseRecord, secureRandom, cipheredTicket,
                        Long.BYTES, cipheredTicket.length - Long.BYTES);
            }

            return null;
        }

        public void outerRotate(SecretRecord secretRecord) {
            rotationLock.lock();
            try {
                this.legacySecret = ondutySecret;
                this.ondutySecret = secretRecord;
            } finally {
                rotationLock.unlock();
            }
        }

        // Rotate the secret record if timeout.
        private void rotateIfOndutyRecordTimeout() {
            if (subscription == null ||
                    System.currentTimeMillis() <= ondutySecret.notAfterMillis) {
                return;
            }

            rotationLock.lock();
            try {
                // double check
                long timeMillis = System.currentTimeMillis();
                if (subscription != null &&
                        timeMillis > ondutySecret.notAfterMillis) {
                    subscription.request(1);
                }
            } finally {
                rotationLock.unlock();
            }
        }
    }

    // The ticket cipher interface.
    private interface TicketCipher {
        byte[] encrypt(SecretRecord secretRecord,
                       SecureRandom secureRandom, byte[] plaintextTicket);

        byte[] decrypt(SecretRecord secretRecord,
                       SecureRandom secureRandom, byte[] cipheredTicket,
                       int ticketOffset, int ticketLength);
    }

    // Note: please don't use a hash algorithm that the output length is
    // less than 32 bytes.
    private enum TicketKeyScheme implements TicketCipher {
        AES_128_GCM_SHA256(
            "SHA-256", 32,
            "AES", 16,
            new AesGcmTicketCipher("AES/GCM/NoPadding", 12)),
        AES_256_GCM_SHA512(
            "SHA-512", 64,
            "AES", 32,
            new AesGcmTicketCipher("AES/GCM/NoPadding", 12)),
        CC20_PO1305_SHA256(
            "SHA-256", 32,
            "ChaCha20", 32,
            new C20P1305TicketCipher("ChaCha20-Poly1305", 12));

        final String hashAlg;
        final int hashLen;

        final String keyAlg;
        final int keySize;
        final TicketCipher cipher;

        TicketKeyScheme(
                String hashAlg, int hashLen,
                String keyAlg, int keySize,
                TicketCipher ticketCipher) {
            this.hashAlg = hashAlg;
            this.hashLen = hashLen;

            this.keyAlg = keyAlg;
            this.keySize = keySize;
            this.cipher = ticketCipher;
        }

        @Override
        public byte[] encrypt(SecretRecord secretRecord,
                SecureRandom secureRandom, byte[] plaintextTicket) {
            return cipher.encrypt(secretRecord, secureRandom, plaintextTicket);
        }

        @Override
        public byte[] decrypt(SecretRecord secretRecord,
                SecureRandom secureRandom, byte[] cipheredTicket,
                int ticketOffset, int ticketLength) {
            return cipher.decrypt(secretRecord,
                    secureRandom, cipheredTicket, ticketOffset, ticketLength);
        }
    }

    private static final class AesGcmTicketCipher implements TicketCipher {
        // As far as we know, all supported GCM cipher suites use 128-bits
        // authentication tags.
        private final static int tagSize = 16;

        private final int ivSize;
        private final String transformation;

        private AesGcmTicketCipher(String transformation, int ivSize) {
            this.transformation = transformation;
            this.ivSize = ivSize;
        }

        @Override
        public byte[] encrypt(SecretRecord secretRecord,
                SecureRandom secureRandom, byte[] plaintextTicket) {
            byte[] ticketIv = new byte[ivSize];
            secureRandom.nextBytes(ticketIv);
            try {
                Cipher cipher = Cipher.getInstance(transformation);
                cipher.init(Cipher.ENCRYPT_MODE, secretRecord.secretKey,
                        new GCMParameterSpec(tagSize * 8, ticketIv),
                        secureRandom);
                cipher.updateAAD(secretRecord.validUntilMillis);
                byte[] encryptedTicket = cipher.doFinal(plaintextTicket);
                return wrapEncryptedTicket(
                        secretRecord.validUntilMillis,
                        ticketIv, encryptedTicket);
            } catch (GeneralSecurityException gse) {    // unlikely to happen
                if (SSLLogger.isOn && SSLLogger.isOn("session")) {
                    SSLLogger.warning("Cannot encrypt session ticket  " + gse);
                }
            }

            return null;
        }

        @Override
        public byte[] decrypt(SecretRecord secretRecord,
                SecureRandom secureRandom, byte[] cipheredTicket,
                int ticketOffset, int ticketLength) {
            if (ticketLength < ivSize) {
                return null;
            }

            try {
                Cipher cipher = Cipher.getInstance(transformation);
                cipher.init(Cipher.DECRYPT_MODE, secretRecord.secretKey,
                        new GCMParameterSpec(tagSize * 8, cipheredTicket,
                                ticketOffset, ivSize),
                        secureRandom);
                cipher.updateAAD(secretRecord.validUntilMillis);
                return cipher.doFinal(cipheredTicket,
                        ticketOffset + ivSize,
                        cipheredTicket.length - ivSize - ticketOffset);
            } catch (AEADBadTagException abte) {
                // Another key could be tried later.
                return new byte[0];
            } catch (GeneralSecurityException gse) {
                if (SSLLogger.isOn && SSLLogger.isOn("session")) {
                    SSLLogger.warning("Cannot decrypt session ticket  " + gse);
                }
            }

            return null;
        }
    }

    private static final class C20P1305TicketCipher implements TicketCipher {
        private final int ivSize;
        private final String transformation;

        private C20P1305TicketCipher(String transformation, int ivSize) {
            this.transformation = transformation;
            this.ivSize = ivSize;
        }

        @Override
        public byte[] encrypt(SecretRecord secretRecord,
                SecureRandom secureRandom, byte[] plaintextTicket) {
            byte[] ticketIv = new byte[ivSize];
            secureRandom.nextBytes(ticketIv);
            try {
                Cipher cipher = Cipher.getInstance(transformation);
                cipher.init(Cipher.ENCRYPT_MODE, secretRecord.secretKey,
                        new IvParameterSpec(ticketIv),
                        secureRandom);
                cipher.updateAAD(secretRecord.validUntilMillis);
                byte[] encryptedTicket = cipher.doFinal(plaintextTicket);
                return wrapEncryptedTicket(
                        secretRecord.validUntilMillis,
                        ticketIv, encryptedTicket);
            } catch (GeneralSecurityException gse) {    // unlikely to happen
                if (SSLLogger.isOn && SSLLogger.isOn("session")) {
                    SSLLogger.warning("Cannot encrypt session ticket  " + gse);
                }
            }

            return null;
        }

        @Override
        public byte[] decrypt(SecretRecord secretRecord,
                SecureRandom secureRandom, byte[] cipheredTicket,
                int ticketOffset, int ticketLength) {
            if (cipheredTicket.length < ivSize) {
                return null;
            }

            try {
                Cipher cipher = Cipher.getInstance(transformation);
                cipher.init(Cipher.DECRYPT_MODE, secretRecord.secretKey,
                        new IvParameterSpec(
                                cipheredTicket, ticketOffset, ivSize),
                        secureRandom);
                cipher.updateAAD(secretRecord.validUntilMillis);
                return cipher.doFinal(cipheredTicket,
                        ticketOffset + ivSize,
                        cipheredTicket.length - ivSize - ticketOffset);
            } catch (AEADBadTagException abte) {
                // Another key could be tried later.
                return new byte[0];
            } catch (GeneralSecurityException gse) {
                if (SSLLogger.isOn && SSLLogger.isOn("session")) {
                    SSLLogger.warning("Cannot decrypt session ticket  " + gse);
                }
            }

            return null;
        }
    }

    private static byte[] wrapEncryptedTicket(
            byte[] validUntilMillis, byte[] ticketIv, byte[] encryptedTicket) {
        byte[] ticket = Arrays.copyOf(validUntilMillis,
                validUntilMillis.length +
                        ticketIv.length + encryptedTicket.length);
        System.arraycopy(ticketIv, 0, ticket,
                validUntilMillis.length, ticketIv.length);
        System.arraycopy(encryptedTicket, 0, ticket,
                validUntilMillis.length + ticketIv.length,
                encryptedTicket.length);

        return ticket;
    }

    /**
     * Default implementation of the key rotation publisher.
     */
    static final class DefaultTicketKeyPublisher
            implements Flow.Publisher<SecretRecord>, KeyManager {
        private static final long KR_PERIOD = TimeUnit.DAYS.toMillis(7);
        private final SecretKey pseudorandomSecret;
        private final TicketKeyScheme ticketKeyScheme;

        DefaultTicketKeyPublisher(X509KeyManager keyManager,
                SecureRandom secureRandom, TicketKeyScheme ticketKeyScheme) {
            this.ticketKeyScheme = ticketKeyScheme;

            SecretKey pseudorandomSecret = null;
            if (SSLConfiguration.useDistributedSessions) {
                // Create the shared pseudorandom secret.
                try {
                    pseudorandomSecret = createSharedPseudorandomSecret(
                            keyManager, ticketKeyScheme);
                } catch (Exception exc) {
                    // Cannot derive distributed friendly ticket secret.
                }
            }

            if (pseudorandomSecret == null) {
                // Create the local private pseudorandom secret.
                if (SSLLogger.isOn && SSLLogger.isOn("session")) {
                    SSLLogger.warning(
                            "Cannot derive distributed friendly ticket secret");
                }

                pseudorandomSecret = createPrivatePseudorandomSecret(
                        secureRandom, ticketKeyScheme);
            }

            this.pseudorandomSecret = pseudorandomSecret;
        }

        @Override
        public void subscribe(Flow.Subscriber<? super SecretRecord> subscriber) {
            subscriber.onSubscribe(new DefaultSubscription(subscriber));
        }

        private class DefaultSubscription implements Flow.Subscription {
            private final Flow.Subscriber<? super SecretRecord> subscriber;

            private DefaultSubscription(
                    Flow.Subscriber<? super SecretRecord> subscriber) {
                this.subscriber = subscriber;
            }

            @Override
            public void request(long l) {
                subscriber.onNext(deriveTicketSecret(
                        pseudorandomSecret, ticketKeyScheme));
            }

            @Override
            public void cancel() {
                // blank
            }
        }

        private static SecretKey createSharedPseudorandomSecret(
                X509KeyManager keyManager, TicketKeyScheme ticketKeyScheme) {
            for (X509Authentication auth : X509Authentication.values()) {
                String[] aliases =
                        keyManager.getServerAliases(auth.keyType, null);
                if (aliases == null || aliases.length == 0) {
                    continue;
                }

                for (String alias : aliases) {
                    if (alias == null || alias.isEmpty()) {
                        continue;
                    }

                    X509Certificate[] serverCerts =
                            keyManager.getCertificateChain(alias);
                    if (serverCerts == null || serverCerts.length == 0) {
                        continue;
                    }

                    PublicKey publicKey = serverCerts[0].getPublicKey();
                    if (publicKey == null) {
                        continue;
                    }

                    byte[] encodedPublicKey = publicKey.getEncoded();
                    if (encodedPublicKey == null ||
                            encodedPublicKey.length == 0) {
                        continue;
                    }

                    PrivateKey privateKey = keyManager.getPrivateKey(alias);
                    if (privateKey == null) {
                        continue;
                    }

                    byte[] encodedPrivateKey = privateKey.getEncoded();
                    if (encodedPrivateKey == null ||
                            encodedPrivateKey.length == 0) {
                        continue;
                    }

                    return derivePseudorandomSecret(encodedPublicKey,
                            encodedPrivateKey,
                            ticketKeyScheme.hashAlg);
                }
            }

            return null;
        }

        private static SecretKey derivePseudorandomSecret(
                byte[] encodedPublicKey,
                byte[] encodedPrivateKey,
                String hashAlgorithm) {
            try {
                // Derive the shared key materials:
                //   SKM = HASH(public key || private key || SKM label)
                MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
                md.update(encodedPublicKey);
                md.update(encodedPrivateKey);
                byte[] sharedKeyMaterials =
                        md.digest("TLS Session Key Material".getBytes());

                // Derive the master key derivation key:
                //    KDK = HKDF_Extract(SKM, KDK label)
                SecretKeySpec ikm =
                        new SecretKeySpec(sharedKeyMaterials, "HKDF-IKM");
                return HKDF.of(hashAlgorithm).extract(
                        "Session Ticket Key Derivation Key".getBytes(),
                        ikm, "HKDF-PPK");
            } catch (NoSuchAlgorithmException | InvalidKeyException nsae) {
                if (SSLLogger.isOn && SSLLogger.isOn("session")) {
                    SSLLogger.warning(
                            "Cannot derive shared key materials", nsae);
                }

                return null;
            }
        }

        private static SecretKey createPrivatePseudorandomSecret(
                SecureRandom secureRandom, TicketKeyScheme scheme) {
            byte[] privateKeyMaterials = new byte[scheme.hashLen];
            secureRandom.nextBytes(privateKeyMaterials);
            return new SecretKeySpec(privateKeyMaterials, "HKDF-PPK");
        }

        private static SecretRecord deriveTicketSecret(SecretKey ppk,
                TicketKeyScheme scheme) {
            try {
                long periodsSince1970 =
                        System.currentTimeMillis() / KR_PERIOD;
                return new SecretRecord(
                        KR_PERIOD * periodsSince1970,           // notBefore
                        KR_PERIOD * (periodsSince1970 + 1),     // notAfter
                        HKDF.of(scheme.hashAlg).expand(ppk,     // secret key
                                Utilities.toByteArray(periodsSince1970),
                                scheme.keySize, scheme.keyAlg));
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                // unlikely
                return null;
            }
        }
    }
}

