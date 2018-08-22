/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptix;

import java.io.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 *
 * JceSecretCipher.java Copyright (c) 2013 by Dr. Herong Yang, herongyang.com
 *
 * @author Administrator
 */
public class JceSecretCipher {

    private static SecretKey readKey(String input, String algorithm)
            throws Exception {
        String fl = input;
        FileInputStream fis = new FileInputStream(fl);
        int kl = fis.available();
        byte[] kb = new byte[kl];
        fis.read(kb);
        fis.close();
        KeySpec ks = null;
        SecretKey ky = null;
        SecretKeyFactory kf = null;
        if (algorithm.equalsIgnoreCase("DES")) {
            ks = new DESKeySpec(kb);
            kf = SecretKeyFactory.getInstance("DES");
            ky = kf.generateSecret(ks);
        } else if (algorithm.equalsIgnoreCase("DESede")) {
            ks = new DESedeKeySpec(kb);
            kf = SecretKeyFactory.getInstance("DESede");
            ky = kf.generateSecret(ks);
        } else {
            ks = new SecretKeySpec(kb, algorithm);
            ky = new SecretKeySpec(kb, algorithm);
        }
        System.out.println();
        System.out.println("KeySpec Object Info: ");
        System.out.println("Saved File = " + fl);
        System.out.println("Length = " + kb.length);
        System.out.println("toString = " + ks.toString());
        System.out.println();
        System.out.println("SecretKey Object Info: ");
        System.out.println("Algorithm = " + ky.getAlgorithm());
        System.out.println("toString = " + ky.toString());
        return ky;
    }

    private static void secretCipher(String algorithm, String mode,
            SecretKey ky, String input, String output) throws Exception {
        Cipher cf = Cipher.getInstance(algorithm);
        if (mode.equalsIgnoreCase("encrypt")) {
            cf.init(Cipher.ENCRYPT_MODE, ky);
        } else if (mode.equalsIgnoreCase("decrypt")) {
            cf.init(Cipher.DECRYPT_MODE, ky);
        } else {
            throw new Exception("Invalid mode: " + mode);
        }
        System.out.println();
        System.out.println("Cipher Object Info: ");
        System.out.println("Block Size = " + cf.getBlockSize());
        System.out.println("Algorithm = " + cf.getAlgorithm());
        System.out.println("Provider = " + cf.getProvider());
        System.out.println("toString = " + cf.toString());
        FileInputStream fis = new FileInputStream(input);
        FileOutputStream fos = new FileOutputStream(output);
        int bufSize = 1024;
        byte[] buf = new byte[bufSize];
        int n = fis.read(buf, 0, bufSize);
        int fisSize = 0;
        int fosSize = 0;
        while (n != -1) {
            fisSize += n;
            byte[] out = cf.update(buf, 0, n);
            fosSize += out.length;
            fos.write(out);
            n = fis.read(buf, 0, bufSize);
        }
        byte[] out = cf.doFinal();
        fosSize += out.length;
        fos.write(out);
        fis.close();
        fos.close();
        System.out.println();
        System.out.println("Cipher Process Info: ");
        System.out.println("Input Size = " + fisSize);
        System.out.println("Output Size = " + fosSize);
    }

    public static void main(String[] a) {
        if (a.length < 5) {
            System.out.println("Usage:");
            System.out.println("java JceSecretCipher algorithm mode"
                    + " keyFile input output");
            return;
        }
        String algorithm = a[0];
        String mode = a[1];
        String keyFile = a[2];
        String input = a[3];
        String output = a[4];
        try {
            SecretKey ky = readKey(keyFile, algorithm);
            secretCipher(algorithm, mode, ky, input, output);
        } catch (Exception e) {
            System.out.println("Exception: " + e);
            return;
        }
    }
}
