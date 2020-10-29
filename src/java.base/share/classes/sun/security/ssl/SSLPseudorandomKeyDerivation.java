/*
 * Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
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

import sun.security.ssl.CipherSuite.HashAlg;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLHandshakeException;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Implementation of the pseudorandom key (of HashLen octets) derivation, which
 * uses the Salt being the current secret state and the Input Keying Material
 * (IKM) being the new secret to be added.  The HKDF-Extract function is used
 * for the key derivation.
 *      HKDF-Extract(salt, IKM) -> PRK
 */
final class SSLPseudorandomKeyDerivation implements SSLKeyDerivation {
    private static final SecretKey sha256ZerosSecret =
            new SecretKeySpec(new byte[32], "TlsZeroSecret");
    private static final SecretKey sha384ZerosSecret =
            new SecretKeySpec(new byte[48], "TlsZeroSecret");

    private final HashAlg hashAlg;
    private final SecretKey saltSecret;
    private final SecretKey ikmSecret;

    private SSLPseudorandomKeyDerivation(
            HandshakeContext context,
            SecretKey saltSecret,
            SecretKey ikmSecret) {
        this.saltSecret = saltSecret;
        this.ikmSecret = ikmSecret;
        this.hashAlg = context.negotiatedCipherSuite.hashAlg;
    }

    static SSLPseudorandomKeyDerivation of(
            HandshakeContext context,
            SecretKey saltSecret,
            SecretKey ikmSecret) {
        return new SSLPseudorandomKeyDerivation(context, saltSecret, ikmSecret);
    }

    @Override
    public SecretKey deriveKey(String algorithm,
            AlgorithmParameterSpec params) throws SSLHandshakeException {
        SecretKey salt = saltSecret;
        if (salt == null) {
            if (hashAlg == HashAlg.H_SHA256) {
                salt = sha256ZerosSecret;
            } else if (hashAlg == HashAlg.H_SHA384) {
                salt = sha384ZerosSecret;
            } else {
                // unlikely, but please update if more hash algorithm
                // get supported in the future.
                throw new SSLHandshakeException(
                        "Unsupported hash algorithm: " + hashAlg);
            }
        }

        SecretKey ikm = ikmSecret;
        if (ikm == null) {
            if (hashAlg == HashAlg.H_SHA256) {
                ikm = sha256ZerosSecret;
            } else if (hashAlg == HashAlg.H_SHA384) {
                ikm = sha384ZerosSecret;
            }
        }

        try {
            return HKDF.of(hashAlg.name).extract(salt, ikm, algorithm);
        } catch (GeneralSecurityException gse) {
            throw (SSLHandshakeException) new SSLHandshakeException(
                    "Could not generate secret").initCause(gse);
        }
    }
}
