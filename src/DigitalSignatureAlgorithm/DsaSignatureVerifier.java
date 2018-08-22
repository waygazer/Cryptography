/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package DigitalSignatureAlgorithm;

import java.io.*;
import java.security.*;
import java.security.spec.*;

/**
 *
 * DsaSignatureVerifier.java Copyright (c) 2013 by Dr. Herong Yang,
 * herongyang.com
 *
 *
 * @author Administrator
 */
public class DsaSignatureVerifier {

    private static PublicKey readPublicKey(String input,
            String algorithm) throws Exception {
        FileInputStream pubKeyStream = new FileInputStream(input);
        int pubKeyLength = pubKeyStream.available();
        byte[] pubKeyBytes = new byte[pubKeyLength];
        pubKeyStream.read(pubKeyBytes);
        pubKeyStream.close();
        X509EncodedKeySpec pubKeySpec
                = new X509EncodedKeySpec(pubKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        System.out.println();
        System.out.println("Public Key Info: ");
        System.out.println("Algorithm = " + pubKey.getAlgorithm());
        return pubKey;
    }

    private static byte[] readSignature(String input)
            throws Exception {
        FileInputStream signStream = new FileInputStream(input);
        int signLength = signStream.available();
        byte[] signBytes = new byte[signLength];
        signStream.read(signBytes);
        signStream.close();
        return signBytes;
    }

    private static boolean verify(String input, String algorithm,
            byte[] sign, PublicKey pubKey) throws Exception {
        Signature sg = Signature.getInstance(algorithm);
        sg.initVerify(pubKey);
        System.out.println();
        System.out.println("Signature Object Info: ");
        System.out.println("Algorithm = " + sg.getAlgorithm());
        System.out.println("Provider = " + sg.getProvider());
        FileInputStream in = new FileInputStream(input);
        int bufSize = 1024;
        byte[] buffer = new byte[bufSize];
        int n = in.read(buffer, 0, bufSize);
        int count = 0;
        while (n != -1) {
            count += n;
            sg.update(buffer, 0, n);
            n = in.read(buffer, 0, bufSize);
        }
        in.close();
        boolean ok = sg.verify(sign);
        System.out.println("Verify Processing Info: ");
        System.out.println("Number of input bytes = " + count);
        System.out.println("Verification result = " + ok);
        return ok;
    }

    public static void main(String[] a) {
        if (a.length < 3) {
            System.out.println("Usage:");
            System.out.println("java DsaSignatureGenerator keyFile"
                    + " msgFile sigFile");
            return;
        }
        String keyFile = a[0];
        String msgFile = a[1];
        String sigFile = a[2];
        String keyAlgo = "DSA";
        String sigAlgo = "SHA1withDSA";
        try {
            PublicKey pubKey = readPublicKey(keyFile, keyAlgo);
            byte[] sign = readSignature(sigFile);
            verify(msgFile, sigAlgo, sign, pubKey);
        } catch (Exception e) {
            System.out.println("Exception: " + e);
            return;
        }
    }

}
