/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package RivestShamirAdleman;

import java.math.BigInteger;
import java.util.Random;

/**
 * PrimeGenerator.java Copyright (c) 2013 by Dr. Herong Yang, herongyang.com
 *
 *
 * @author Administrator
 */
public class PrimeGenerator {

    public static void main(String[] a) {
        if (a.length < 2) {
            System.out.println("Usage:");
            System.out.println("java PrimeGenerator length certainty");
            return;
        }
        int length = Integer.parseInt(a[0]);
        int certainty = Integer.parseInt(a[1]);
        Random rnd = new Random();
        long t1 = System.currentTimeMillis();
        BigInteger p = new BigInteger(length, certainty, rnd);
        long t2 = System.currentTimeMillis();
        boolean ok = p.isProbablePrime(certainty);
        long t3 = System.currentTimeMillis();
        BigInteger two = new BigInteger("2");
        System.out.println("Probable prime: " + p);
        System.out.println("Validation: " + ok);
        System.out.println("Bit length: " + length);
        System.out.println("Certainty: " + certainty);
        System.out.println("Probability (%): "
                + (100.0 - 100.0 / (two.pow(certainty)).doubleValue()));
        System.out.println("Generation time (milliseconds): " + (t2 - t1));
        System.out.println("Validation time (milliseconds): " + (t3 - t2));
    }
}
