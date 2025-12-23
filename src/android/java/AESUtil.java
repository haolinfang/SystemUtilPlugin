package cordova.plugins;

import android.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class AESUtil {

    public static String encryptCBC(String plaintext, String key, String iv) throws Exception {
        if (key == null || key.length() == 0) {
            throw new IllegalArgumentException("Key cannot be empty");
        }

        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        byte[] ivBytes = (iv != null && iv.length() >= 16)
            ? iv.substring(0, 16).getBytes(StandardCharsets.UTF_8)
            : key.getBytes(StandardCharsets.UTF_8);

        if (ivBytes.length > 16) {
            byte[] temp = new byte[16];
            System.arraycopy(ivBytes, 0, temp, 0, 16);
            ivBytes = temp;
        }

        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.encodeToString(encryptedBytes, Base64.NO_WRAP);
    }

    public static String decryptCBC(String encryptedBase64, String key, String iv) throws Exception {
        if (key == null || key.length() == 0) {
            throw new IllegalArgumentException("Key cannot be empty");
        }

        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        byte[] ivBytes = (iv != null && iv.length() >= 16)
            ? iv.substring(0, 16).getBytes(StandardCharsets.UTF_8)
            : key.getBytes(StandardCharsets.UTF_8);

        if (ivBytes.length > 16) {
            byte[] temp = new byte[16];
            System.arraycopy(ivBytes, 0, temp, 0, 16);
            ivBytes = temp;
        }

        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encryptedBytes = Base64.decode(encryptedBase64, Base64.NO_WRAP);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}