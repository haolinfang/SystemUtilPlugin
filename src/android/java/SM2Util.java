package cordova.plugins;

import android.util.Base64;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

public class SM2Util {
    
    static {
        // 添加BouncyCastle提供者
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static String encryptWithSM2(String plaintext, String publicKeyStr) throws Exception {
        try {
            PublicKey publicKey = getPublicKeyFromString(publicKeyStr);
            
            Cipher cipher = Cipher.getInstance("SM2", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes("UTF-8"));
            
            return Base64.encodeToString(encryptedBytes, Base64.NO_WRAP);
        } catch (Exception e) {
            // 如果SM2加密失败，回退到RSA
            return RSAUtil.encryptWithRSA(plaintext, publicKeyStr);
        }
    }

    public static PublicKey getPublicKeyFromString(String publicKeyStr) throws Exception {
        String publicKeyPEM = publicKeyStr
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN EC PUBLIC KEY-----", "")
                .replace("-----END EC PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] encoded = Base64.decode(publicKeyPEM, Base64.DEFAULT);

        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return keyFactory.generatePublic(keySpec);
    }
}