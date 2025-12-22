package cordova.plugins;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.device.Device;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class SystemUtilPlugin extends CordovaPlugin {

  private static final String TAG = "SystemUtilPlugin";
  private static final String PREFS_NAME = "SystemUtilPrefs";

  private String key = "";
  private String iv = "";
  private static String t = "";
  private static String p = "";
  private static String s = "";
  private static String ps = "";

  @Override
  public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
    if (action.equals("putIn")) {
      return putIn(args, callbackContext);
    } else if (action.equals("putPub")) {
      return putPub(args, callbackContext);
    } else if (action.equals("putOut")) {
      return putOut(args, callbackContext);
    } else if (action.equals("getPub")) {
      return getPub(args, callbackContext);
    } else {
      callbackContext.error("未知的action: " + action);
      return false;
    }
  }

  // 保存数据到 SharedPreferences
  private void savePreference(String key, String value) {
    Context context = cordova.getActivity().getApplicationContext();
    SharedPreferences sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    SharedPreferences.Editor editor = sharedPreferences.edit();
    editor.putString(key, value);
    editor.apply();
  }

  // 从 SharedPreferences 获取数据
  private String getPreference(String key) {
    Context context = cordova.getActivity().getApplicationContext();
    SharedPreferences sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    return sharedPreferences.getString(key, "");
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
      JSONObject obj = args.getJSONObject(0);
      String pubKey = obj.optString("pubKey", "");
      savePreference("pubKey", AESUtil.encryptCBC(pubKey, key, iv));
      callbackContext.success();
    } catch (JSONException e) {
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
          callbackContext.success(AESUtil.decryptCBC(s, key, iv));
          break;
        case "all":
          JSONObject all = new JSONObject();
          all.put("t", t);
          all.put("p", p);
          all.put("s", AESUtil.decryptCBC(s, key, iv));
          callbackContext.success(all);
          break;
        case "sign":
          JSONObject result = new JSONObject();
          String a1 = obj.optString("a1", "");
          String a2 = obj.optString("a2", "");
          String a3 = obj.optString("a3", "");
          String m1 = a1 + a2 + a3;
          String m2 = "";
          if (!TextUtils.isEmpty(t)) {
            m1 += t;
          }
          if (!TextUtils.isEmpty(Device.uuid)) {
            m2 += Device.uuid;
          }
          String md51 = "";
          String md52 = "";
          if (!TextUtils.isEmpty(m1)) {
            md51 = MD5Util.md5(m1);
          }
          if (!TextUtils.isEmpty(m2)) {
            md52 = MD5Util.md5(m2);
          }
          String md5Result = "";
          if (!TextUtils.isEmpty(md51)) {
            md5Result += md51;
          }
          if (!TextUtils.isEmpty(md52)) {
            md5Result += md52;
          }
          result.put("b", md5Result);

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

  private boolean getPub(JSONArray args, CallbackContext callbackContext) {
    try {
      JSONObject obj = args.getJSONObject(0);
      String name = obj.optString("name", "");
      switch (name) {
        case "first":
          callbackContext.success(AESUtil.decryptCBC(s, key, iv));
          break;
        case "secend":
          String pubKey = getPreference("pubKey");
          callbackContext.success(AESUtil.decryptCBC(pubKey, key, iv));
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