package cordova.plugins;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
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

  @Override
  public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
    if (action.equals("putIn")) {
      return putIn(args, callbackContext);
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