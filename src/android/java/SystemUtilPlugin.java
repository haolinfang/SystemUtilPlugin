package cordova.plugins;

import android.content.Context;
import android.java.SharedPrefsUtil;
import android.text.TextUtils;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.device.Device;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class SystemUtilPlugin extends CordovaPlugin {

  private static final String TAG = "SystemUtilPlugin";
  private String key = "a9s8d7f6g5h4j3k2";
  private String iv = "z1x2c3v4b5n6m7q8";
  private static String t = "";
  private static String p = "";
  private static String s = "Cu34hcmWCXkHft5FmI2pP0SoekDRaj2woG//1Tj4vV0CR+OeCCj1ci3Y6Ln3UKPr2+KFQOfOykts8Bg1NNI/8PvCbKQUNMrn3u3IZNMP3YrlcnD5yJcJHmlwnMBZX6Ruw3KyznynpFJGwTlyJgiwrTRsNjASV5i5WQlwhcXECSgqKjN9Uug2aBbIfho73GQb";
  public static String fin1Key = "mEGnz+o7k9+gGeFqNvImvJiX5+wor5FK7LtD+1hUlJ5p6VLE3d/0uNymciQEoTUrTWlwxoqQT/Ogkg3zLtIlN8n5wlfCUuhzn4JFTPZXV/pVbX7nKcvffaGfbN4Z6IJteNktXRTzJvPeI+EKHM5vlqIn+NFfk9AUptm20Rtyb+hdc0Jkrrr05SRR4vJDy9RHU1LrWyh6DjybSFfdh9jH40iWhaBmlWYJMBiuQPnidpSyGEy5POUIA+nt6TBoEmtnPO6AxXnx4ZSo68l2oRiPVQQkZBL6LEvH7cxz6qMZ1Y/rXZQ7TzU7osswnp0CLkuZW1NsCdxP0VcUGNjs0LzTyOP0RrqtrmcGWiaggAKo3sA9TtOpu/YMflPWToIEh0eRBd6WIoc732KiKq65NJ8wIppr0wwGqz3mGpPV92xktQw9l4euaT4FujbxP5yiXylI9CyKbHEAU5aCYMb3rkvWTWgGB8CjSuaYGfH9x/NlX4Pll9dBgjQ6k6PHv8nTBypiMrAg1Z+iOnAcKeKU6O70sA==";
  public static String fac1Key = "mEGnz+o7k9+gGeFqNvImvJiX5+wor5FK7LtD+1hUlJ4zjCzJknjy4dDnZLawGRqA2OnppD9qLsRlPMwsIab2Nm7wFXuCROXov/taWtK94wOU2ckosa5H7jfvHxo/hIuHTPh39oFd3EaL4auM+ePx0cJkWA1H0Jg+Zf+bpp8Amf9f/66XW6qzKekKlhEgmCt3mZbqbPeP84THxcXaYb0Dg13XBrVK9QE5MIFqD9wx/poOb698M0vo/Pfax1hljJm57ZgD2ScVJp96ES+3NrHeNc8noCCvn71iSnwFEgsuHFzLHKSljQsbZqafMLzkmT5Xze9TCS2tKCU3XVRmL8pYo37GoWTfCbCwv3diCaJA+VgaKKX7Z4tpqS5vfxs0wHohjILIWcQeAtbhViVFAWQhlqCPun0pD/OUVWnrOQPswFjtIma8Y2bWTd93HDC2/uCRsObGSiASXjgJUJ3NTcNgK1v6SmzFocR1NoXQtv8r2DLK4rfWlZSixFQW5yCtK3yGlgRTtGDzkPHzznDyQq2mbQ==";

  @Override
  protected void pluginInitialize() {
    super.pluginInitialize();
    Context context = cordova.getActivity().getApplicationContext();
    SharedPrefsUtil.savePreference(context, "fin1Key", fin1Key);
    SharedPrefsUtil.savePreference(context, "fac1Key", fac1Key);
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
      if (!"".equals(fingerKey)) {
        String encryptedPubKey = AESUtil.encryptCBC(fingerKey, key, iv);
        SharedPrefsUtil.savePreference(context, "fin2Key", encryptedPubKey);
      }
      if (!"".equals(faceKey)) {
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
}