package cordova.plugins;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SM3Util {
    public static String sm3(String input) {
        try {
            // SM3的算法标识，需要BC库支持
            MessageDigest md = MessageDigest.getInstance("SM3");
            byte[] digest = md.digest(input.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}