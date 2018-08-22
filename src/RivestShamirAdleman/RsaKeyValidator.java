/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package RivestShamirAdleman;

import java.math.BigInteger;
import java.util.Random;
import java.io.*;

/**
 * RsaKeyValidator.java Copyright (c) 2013 by Dr. Herong Yang, herongyang.com
 *
 *
 * @author Administrator
 */
public class RsaKeyValidator {

    private BigInteger n, e, d;
// Reading in RSA public key and private key

    RsaKeyValidator(String input) {
        try {
            BufferedReader in = new BufferedReader(new FileReader(input));
            String line = in.readLine();
            while (line != null) {
                if (line.indexOf("Modulus: ") >= 0) {
                    n = new BigInteger(line.substring(9));
                }
                if (line.indexOf("Public key: ") >= 0) {
                    e = new BigInteger(line.substring(12));
                }
                if (line.indexOf("Private key: ") >= 0) {
                    d = new BigInteger(line.substring(13));
                }
                line = in.readLine();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        System.out.println("--- Reading public key and private key ---");
        System.out.println("Modulus: " + n);
        System.out.println("Key size: " + n.bitLength());
        System.out.println("Public key: " + e);
        System.out.println("Private key: " + d);
    }
// Testing encryption and description

    public void test() {
        Random rnd = new Random();
        int size = rnd.nextInt(n.bitLength() - 1);
        BigInteger text = new BigInteger(size, rnd);
        BigInteger cipher = text.modPow(e, n);
        BigInteger decrypted = cipher.modPow(d, n);
        boolean isPassed = text.equals(decrypted);
        System.out.println("--- RSA encryption test ---");
        System.out.println("Is test passed: " + isPassed);
        System.out.println("Original text: " + text);
        System.out.println("Cipher text: " + cipher);
        System.out.println("Decrypted text: " + decrypted);
    }

    public static void main(String[] a) {
        if (a.length < 1) {
            System.out.println("Usage:");
            System.out.println("java RsaKeyValidator input");
            return;
        }
        String input = a[0];
        RsaKeyValidator validator = new RsaKeyValidator(input);
        validator.test();
        validator.test();
        validator.test();
    }
}
