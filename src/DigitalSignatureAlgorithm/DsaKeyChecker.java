/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package DigitalSignatureAlgorithm;

import java.io.*;
import java.math.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;

/**
 *
 * DsaKeyChecker.java Copyright (c) 2013 by Dr. Herong Yang
 *
 *
 * @author Administrator
 */
public class DsaKeyChecker {

    private static KeyPair readKeyPair(String input,
            String algorithm) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        String priKeyFile = input + ".pri";
        FileInputStream priKeyStream = new FileInputStream(priKeyFile);
        int priKeyLength = priKeyStream.available();
        byte[] priKeyBytes = new byte[priKeyLength];
        priKeyStream.read(priKeyBytes);
        priKeyStream.close();
        PKCS8EncodedKeySpec priKeySpec
                = new PKCS8EncodedKeySpec(priKeyBytes);
        PrivateKey priKey = keyFactory.generatePrivate(priKeySpec);
        String pubKeyFile = input + ".pub";
        FileInputStream pubKeyStream = new FileInputStream(pubKeyFile);
        int pubKeyLength = pubKeyStream.available();
        byte[] pubKeyBytes = new byte[pubKeyLength];
        pubKeyStream.read(pubKeyBytes);
        pubKeyStream.close();
        X509EncodedKeySpec pubKeySpec
                = new X509EncodedKeySpec(pubKeyBytes);
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        return new KeyPair(pubKey, priKey);
    }

    private static void checkDsaKeyPair(KeyPair pair) {
        DSAPublicKey pubKey = (DSAPublicKey) pair.getPublic();
        DSAPrivateKey priKey = (DSAPrivateKey) pair.getPrivate();
        DSAParams params = priKey.getParams();
        BigInteger p = params.getP();
        BigInteger q = params.getQ();
        BigInteger g = params.getG();
        BigInteger x = priKey.getX();
        BigInteger y = pubKey.getY();
        System.out.println();
        System.out.println("DSA Key Parameters: ");
        System.out.println("p = " + p);
        System.out.println("q = " + q);
        System.out.println("g = " + g);
        System.out.println("x = " + x);
        System.out.println("y = " + y);
        System.out.println();
        System.out.println("DSA Key Verification: ");
        System.out.println("What's key size? " + p.bitLength());
        System.out.println("Is p a prime? " + p.isProbablePrime(200));
        System.out.println("Is q a prime? " + q.isProbablePrime(200));
        System.out.println("Is p-1 mod q == 0? "
                + p.subtract(BigInteger.ONE).mod(q));
        System.out.println("Is g**q mod p == 1? " + g.modPow(q, p));
        System.out.println("Is q > x? " + (q.compareTo(x) == 1));
        System.out.println("Is g**x mod p == y? " + g.modPow(x, p).equals(y));
    }

    public static void main(String[] a) {
        if (a.length < 1) {
            System.out.println("Usage:");
            System.out.println("java DsaKeyChecker input");
            return;
        }
        String input = a[0];
        String algorithm = "DSA";
        try {
            KeyPair pair = readKeyPair(input, algorithm);
            checkDsaKeyPair(pair);
        } catch (Exception e) {
            System.out.println("Exception: " + e);
            return;
        }
    }
}
