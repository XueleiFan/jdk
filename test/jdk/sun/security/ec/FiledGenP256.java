/*
 * Copyright (C) 2022 THL A29 Limited, a Tencent company. All rights reserved.
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

/*
 * @test
 * @bug 8294248
 * @summary Use less limbs for P256 in EC implementation
 * @modules java.base/sun.security.util.math:+open
 *          java.base/sun.security.util.math.intpoly:+open
 */

import sun.security.util.math.IntegerModuloP;
import sun.security.util.math.intpoly.IntegerPolynomial;
import sun.security.util.math.intpoly.IntegerPolynomialP256;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.Random;

public class FiledGenP256 {
    public static void main(String[] args) throws Exception {
        IntegerPolynomialP256 ip256 = IntegerPolynomialP256.ONE;
        Field numLimbsField =
                IntegerPolynomial.class.getDeclaredField("numLimbs");
        numLimbsField.setAccessible(true);
        int numLimbs = (int) numLimbsField.get(ip256);

        Field bitsPerLimbField =
                IntegerPolynomial.class.getDeclaredField("bitsPerLimb");
        bitsPerLimbField.setAccessible(true);
        int bitsPerLimb = (int) bitsPerLimbField.get(ip256);

        Field maxAddsField =
                IntegerPolynomial.class.getDeclaredField("maxAdds");
        maxAddsField.setAccessible(true);
        int maxAdds = (int) maxAddsField.get(ip256);

        Field modulusField =
                IntegerPolynomial.class.getDeclaredField("modulus");
        modulusField.setAccessible(true);
        BigInteger modulus = (BigInteger) modulusField.get(ip256);

        int[] matrix = new int[] {
                0, 1, 2, 3, 4, 5, maxAdds + (new Random()).nextInt(32)
        };
        for (int checkedAdds : matrix) {
            BigInteger vi =
                    BigInteger.TWO.pow(bitsPerLimb).subtract(BigInteger.ONE);
            System.out.println(vi.toString(16));
            IntegerModuloP imp = ip256.getElement(vi);
            long limbValue = vi.longValue();
            Field limbsField = imp.getClass()
                    .getSuperclass().getDeclaredField("limbs");
            limbsField.setAccessible(true);
            long[] limbs = (long[])limbsField.get(imp);
            if (limbs.length != numLimbs) {
                throw new RuntimeException();
            }

            for (int i = 0; i < limbs.length; i++) {
                limbs[i] = limbValue;
            }

            BigInteger v = imp.asBigInteger().mod(modulus);
    dumpLimbs(limbs);
    System.out.println("Check " + checkedAdds + " adds");
            for (int i = 0; i < checkedAdds; i++) {
                imp = imp.add(imp);

    System.out.println(imp.asBigInteger().toString(16));
    long[] nlimbs = (long[])limbsField.get(imp);
    dumpLimbs(nlimbs);
            }
            for (int i = 0; i < checkedAdds; i++) {
                v = v.add(v).mod(modulus);
            }
    System.out.println(v.toString(16));

            BigInteger bi = imp.asBigInteger();
    System.out.println(v.toString(16));
    System.out.println(v.mod(modulus).toString(16));

            BigInteger biSquared = bi.multiply(bi).mod(modulus);
    System.out.println("Computed with BigInteger:");
    System.out.println(biSquared.toString(16));

            BigInteger impSquared = imp.square().asBigInteger();

    System.out.println("Computed with IntegerPolynomial:");
    System.out.println(impSquared.toString(16));
            if (!impSquared.equals(biSquared)) {
                throw new RuntimeException();
            }
        }
    }

    private static void dumpLimbs(long[] limbs) {
        for (long limb : limbs) {
            System.out.println(Long.toHexString(limb) + " ");
        }
    }
}
