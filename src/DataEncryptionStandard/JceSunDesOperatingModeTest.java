/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package DataEncryptionStandard;

import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 *
 * JceSunDesOperationModeTest.java Copyright (c) 2013 by Dr. Herong Yang,
 * herongyang.com
 *
 *
 * @author Administrator
 */
public class JceSunDesOperatingModeTest {

    public static byte[] hexToBytes(String str) {
        if (str == null) {
            return null;
        } else if (str.length() < 2) {
            return null;
        } else {
            int len = str.length() / 2;
            byte[] buffer = new byte[len];
            for (int i = 0; i < len; i++) {
                buffer[i] = (byte) Integer.parseInt(
                        str.substring(i * 2, i * 2 + 2), 16);
            }
            return buffer;
        }
    }

    public static String bytesToHex(byte[] data) {
        if (data == null) {
            return null;
        } else {
            int len = data.length;
            String str = "";
            for (int i = 0; i < len; i++) {
                if ((data[i] & 0xFF) < 16) {
                    str = str + "0"
                            + java.lang.Integer.toHexString(data[i] & 0xFF);
                } else {
                    str = str
                            + java.lang.Integer.toHexString(data[i] & 0xFF);
                }
            }
            return str.toUpperCase();
        }
    }

    public static void main(String[] a) {
        if (a.length < 1) {
            System.out.println("Usage:");
            System.out.println(
                    "java JceSunDesOperationModeTest 1/2/3/4");
            return;
        }
        String test = a[0];
        try {
            byte[] theKey = null;
            byte[] theIVp = null;
            byte[] theMsg = null;
            byte[] theExp = null;
            String algorithm = null;
            if (test.equals("1")) {
                algorithm = "DES/ECB/NoPadding";
                theKey = hexToBytes("0123456789ABCDEF");
                theMsg = hexToBytes(
                        "4E6F77206973207468652074696D6520666F7220616C6C20");
// "Now is the time for all "
                theExp = hexToBytes(
                        "3FA40E8A984D43156A271787AB8883F9893D51EC4B563B53");
            } else if (test.equals("2")) {
                algorithm = "DES/CBC/NoPadding";
                theKey = hexToBytes("0123456789ABCDEF");
                theIVp = hexToBytes("1234567890ABCDEF");
                theMsg = hexToBytes(
                        "4E6F77206973207468652074696D6520666F7220616C6C20");
// "Now is the time for all "
                theExp = hexToBytes(
                        "E5C7CDDE872BF27C43E934008C389C0F683788499A7C05F6");
            } else if (test.equals("3")) {
                algorithm = "DES/CFB/NoPadding";
                theKey = hexToBytes("0123456789ABCDEF");
                theIVp = hexToBytes("1234567890ABCDEF");
                theMsg = hexToBytes(
                        "4E6F77206973207468652074696D6520666F7220616C6C20");
// "Now is the time for all "
                theExp = hexToBytes(
                        "F3096249C7F46E51A69E839B1A92F78403467133898EA622");
            } else if (test.equals("4")) {
                algorithm = "DES/OFB/NoPadding";
                theKey = hexToBytes("0123456789ABCDEF");
                theIVp = hexToBytes("1234567890ABCDEF");
                theMsg = hexToBytes(
                        "4E6F77206973207468652074696D6520666F7220616C6C20");
// "Now is the time for all "
                theExp = hexToBytes(
                        "F3096249C7F46E5135F24A242EEB3D3F3D6D5BE3255AF8C3");
            } else {
                System.out.println("Wrong option. For help enter:");
                System.out.println("java JceSunDesOperationModeTest");
                return;
            }
            KeySpec ks = new DESKeySpec(theKey);
            SecretKeyFactory kf
                    = SecretKeyFactory.getInstance("DES");
            SecretKey ky = kf.generateSecret(ks);
            Cipher cf = Cipher.getInstance(algorithm);
            if (theIVp == null) {
                cf.init(Cipher.ENCRYPT_MODE, ky);
            } else {
                AlgorithmParameterSpec aps = new IvParameterSpec(theIVp);
                cf.init(Cipher.ENCRYPT_MODE, ky, aps);
            }
            byte[] theCph = cf.doFinal(theMsg);
            System.out.println("Key : " + bytesToHex(theKey));
            if (theIVp != null) {
                System.out.println("IV : " + bytesToHex(theIVp));
            }
            System.out.println("Message : " + bytesToHex(theMsg));
            System.out.println("Cipher : " + bytesToHex(theCph));
            System.out.println("Expected: " + bytesToHex(theExp));
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
    }
}