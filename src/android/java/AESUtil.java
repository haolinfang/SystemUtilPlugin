package cordova.plugins;

import android.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * AES 加密/解密工具类 (CBC 模式)
 * 与 JavaScript CryptoJS 兼容版本
 */
public class AESUtil {

  /**
   * AES 加密 (CBC 模式)
   * @param plaintext 明文
   * @param key 密钥 (16/24/32字节)
   * @param iv 初始化向量 (16字节)
   * @return Base64 编码的加密结果
   * @throws Exception 加密异常
   */
  public static String encryptCBC(String plaintext, String key, String iv) throws Exception {
    // 验证密钥和IV
    if (key == null || key.length() == 0) {
      throw new IllegalArgumentException("Key cannot be empty");
    }

    // 使用密钥和IV
    byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
    byte[] ivBytes = (iv != null && iv.length() >= 16)
      ? iv.substring(0, 16).getBytes(StandardCharsets.UTF_8)  // 取前16字节
      : key.getBytes(StandardCharsets.UTF_8);  // 如果IV不够，用key作为IV

    // 确保IV长度为16字节
    if (ivBytes.length > 16) {
      byte[] temp = new byte[16];
      System.arraycopy(ivBytes, 0, temp, 0, 16);
      ivBytes = temp;
    }

    // 创建密钥和IV规范
    SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
    IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

    // 创建Cipher实例 (CBC/PKCS5Padding 对应 JS 的 PKCS7)
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

    // 执行加密
    byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

    // 返回Base64编码结果
    return Base64.encodeToString(encryptedBytes, Base64.DEFAULT);
  }

  /**
   * AES 解密 (CBC 模式)
   * @param encryptedBase64 Base64编码的密文
   * @param key 密钥
   * @param iv 初始化向量
   * @return 解密后的明文
   * @throws Exception 解密异常
   */
  public static String decryptCBC(String encryptedBase64, String key, String iv) throws Exception {
    // 验证参数
    if (key == null || key.length() == 0) {
      throw new IllegalArgumentException("Key cannot be empty");
    }

    // 使用密钥和IV
    byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
    byte[] ivBytes = (iv != null && iv.length() >= 16)
      ? iv.substring(0, 16).getBytes(StandardCharsets.UTF_8)
      : key.getBytes(StandardCharsets.UTF_8);

    // 确保IV长度为16字节
    if (ivBytes.length > 16) {
      byte[] temp = new byte[16];
      System.arraycopy(ivBytes, 0, temp, 0, 16);
      ivBytes = temp;
    }

    // 创建密钥和IV规范
    SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
    IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

    // 创建Cipher实例
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

    // 解码Base64并执行解密
    byte[] encryptedBytes = Base64.decode(encryptedBase64, Base64.DEFAULT);
    byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

    // 返回解密结果
    return new String(decryptedBytes, StandardCharsets.UTF_8);
  }

  /**
   * AES 加密 (ECB 模式)
   * @param plaintext 明文
   * @param key 密钥
   * @return Base64 编码的加密结果
   * @throws Exception 加密异常
   */
  public static String encryptECB(String plaintext, String key) throws Exception {
    byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
    SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

    // ECB 模式不需要 IV
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

    byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
    return Base64.encodeToString(encryptedBytes, Base64.DEFAULT);
  }

  /**
   * AES 解密 (ECB 模式)
   * @param encryptedBase64 Base64编码的密文
   * @param key 密钥
   * @return 解密后的明文
   * @throws Exception 解密异常
   */
  public static String decryptECB(String encryptedBase64, String key) throws Exception {
    byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
    SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

    byte[] encryptedBytes = Base64.decode(encryptedBase64, Base64.DEFAULT);
    byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

    return new String(decryptedBytes, StandardCharsets.UTF_8);
  }

  /**
   * 生成随机IV (16字节)
   * @return Base64编码的IV
   */
  public static String generateRandomIV() {
    byte[] iv = new byte[16];
    new SecureRandom().nextBytes(iv);
    return Base64.encodeToString(iv, Base64.DEFAULT);
  }
}
