package cordova.plugins;

import android.util.Base64;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

public class RSAUtil {

    public static String encryptWithRSA(String plaintext, String publicKeyStr) throws Exception {
        PublicKey publicKey = getPublicKeyFromString(publicKeyStr);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes("UTF-8"));

        return Base64.encodeToString(encryptedBytes, Base64.NO_WRAP);
    }

    public static PublicKey getPublicKeyFromString(String publicKeyStr) throws Exception {
        String publicKeyPEM = publicKeyStr
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] encoded = Base64.decode(publicKeyPEM, Base64.DEFAULT);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return keyFactory.generatePublic(keySpec);
    }
}