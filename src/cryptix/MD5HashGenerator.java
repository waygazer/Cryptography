/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptix;

import cryptix.jce.provider.CryptixCrypto;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Administrator
 */
public class MD5HashGenerator {

    static {
        try {
            MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            Security.addProvider(new CryptixCrypto());
        }
    }

    public MD5HashGenerator() {
        super();
    }

    /**
     * @param args
     */
    public static void main(String[] args) {
        try {
            System.out.println("Hash: " + md5(args[0]));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MD5HashGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public static String md5(String input) throws NoSuchAlgorithmException {
        String result = input;
        if (input != null) {
            MessageDigest md = MessageDigest.getInstance("MD5"); //or "SHA-1"
            md.update(input.getBytes());
            BigInteger hash = new BigInteger(1, md.digest());
            result = hash.toString(16);
            while (result.length() < 32) { //40 for SHA-1
                result = "0" + result;
            }
        }
        return result;
    }
}