package cordova.plugins;

import android.content.Context;
import android.text.TextUtils;
import android.util.Log;
import com.plugin.keystore.KeyStore;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.device.Device;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class SystemUtilPlugin extends CordovaPlugin {

  private static final String TAG = "SystemUtilPlugin";
  private String key = "";
  private String iv = "";
  private static String t = "";
  private static String p = "";
  private static String s = "";
  private static String decryptedS = ""; // 新增：存储解密后的s值
  
  @Override
  protected void pluginInitialize() {
    super.pluginInitialize();
    
    try {
      // 初始化 KeyStore，这会自动加载 keystore.so
      KeyStore keyStore = new KeyStore();
      
      // 从 native 库获取所有密钥
      key = keyStore.getAESKey();
      iv = keyStore.getAESIV();
      s = keyStore.getStringS();
      
      // 在初始化时直接解密s，后面直接使用decryptedS
      if (!TextUtils.isEmpty(s) && !TextUtils.isEmpty(key) && !TextUtils.isEmpty(iv)) {
        try {
          decryptedS = AESUtil.decryptCBC(s, key, iv);
          Log.d(TAG, "Native KeyStore initialized successfully, s decrypted");
        } catch (Exception e) {
          Log.e(TAG, "Failed to decrypt s: " + e.getMessage());
          decryptedS = "";
        }
      } else {
        Log.e(TAG, "Key, iv or s is empty, cannot decrypt s");
      }
      
      Log.d(TAG, "Native KeyStore initialized successfully");
      
    } catch (Exception e) {
      Log.e(TAG, "Failed to initialize native KeyStore: " + e.getMessage());
    }
  }

  @Override
  public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
    if (action.equals("putIn")) {
      return putIn(args, callbackContext);
    } else if (action.equals("putPub")) {
      return putPub(args, callbackContext);
    } else if (action.equals("putOut")) {
      return putOut(args, callbackContext);
    } else {
      callbackContext.error("未知的action: " + action);
      return false;
    }
  }

  private boolean putIn(JSONArray args, CallbackContext callbackContext) {
    try {
      JSONObject obj = args.getJSONObject(0);
      t = obj.optString("accessToken", "");
      p = obj.optString("prvKey", "");
      callbackContext.success();
    } catch (JSONException e) {
      callbackContext.error("缓存数字信封失败");
    }
    return true;
  }

  private boolean putPub(JSONArray args, CallbackContext callbackContext) {
    try {
      Context context = cordova.getActivity().getApplicationContext();
      JSONObject obj = args.getJSONObject(0);
      String fingerKey = obj.optString("fingerKey", "");
      String faceKey = obj.optString("faceKey", "");
      
      if (!TextUtils.isEmpty(fingerKey)) {
        String encryptedPubKey = AESUtil.encryptCBC(fingerKey, key, iv);
        SharedPrefsUtil.savePreference(context, "fin2Key", encryptedPubKey);
      }
      if (!TextUtils.isEmpty(faceKey)) {
        String encryptedPubKey = AESUtil.encryptCBC(faceKey, key, iv);
        SharedPrefsUtil.savePreference(context, "fac2Key", encryptedPubKey);
      }
      callbackContext.success();
    } catch (Exception e) {
      callbackContext.error("缓存指纹公钥失败");
    }
    return true;
  }

  private boolean putOut(JSONArray args, CallbackContext callbackContext) {
    try {
      JSONObject obj = args.getJSONObject(0);
      String name = obj.optString("name", "");
      
      switch (name) {
        case "t":
          callbackContext.success(t);
          break;
        case "p":
          callbackContext.success(p);
          break;
        case "s":
          // 直接返回已经解密的s值
          callbackContext.success(decryptedS);
          break;
        case "all":
          JSONObject all = new JSONObject();
          all.put("t", t);
          all.put("p", p);
          // 直接使用已经解密的s值
          all.put("s", decryptedS);
          callbackContext.success(all);
          break;
        case "sign":
          JSONObject result = new JSONObject();
          String a1 = obj.optString("a1", "");
          String a2 = obj.optString("a2", "");
          String a3 = obj.optString("a3", "");
          
          // 1. 使用SM3加密(a1 + a2 + a3 + t)
          String m1 = a1 + a2 + a3;
          if (!TextUtils.isEmpty(t)) {
            m1 += t;
          }
          String sm3Hash = SM3Util.sm3(m1);
          
          // 2. 获取设备UUID
          String deviceUuid = Device.uuid != null ? Device.uuid : "";
          
          // 3. 直接使用已经解密的s值作为SM2公钥
          String sm2PublicKey = decryptedS;
          
          // 4. 使用SM2加密(sm3Hash + deviceUuid)
          String toBeEncrypted = sm3Hash + deviceUuid;
          String encryptedData = "";
          if (!TextUtils.isEmpty(sm2PublicKey) && !TextUtils.isEmpty(toBeEncrypted)) {
            encryptedData = SM2Util.encryptWithSM2(toBeEncrypted, sm2PublicKey);
          }
          
          result.put("b", encryptedData);
          callbackContext.success(result);
          break;
        default:
          callbackContext.error("参数错误");
          break;
      }
    } catch (Exception e) {
      callbackContext.error(e.getMessage());
    }
    return true;
  }
}