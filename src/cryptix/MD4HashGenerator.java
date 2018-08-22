/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptix;

import cryptix.jce.provider.CryptixCrypto;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import org.apache.commons.codec.binary.Hex;

/**
 *
 * @author Administrator
 */
public class MD4HashGenerator {

    static {
        try {
            MessageDigest.getInstance("MD4");
        } catch (NoSuchAlgorithmException e) {
            Security.addProvider(new CryptixCrypto());
        }
    }

    public MD4HashGenerator() {
        super();
    }

    /**
     * @param args
     */
    public static void main(String[] args) {

        System.out.println("Hash: " + new String(Hex.encodeHex(md4(args[0]))));

    }

    private static byte[] md4(String input) {
        try {
            MessageDigest digester = MessageDigest.getInstance("MD4");
            return digester.digest(input.getBytes("UnicodeLittleUnmarked"));
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }
}