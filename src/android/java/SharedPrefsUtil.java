package cordova.plugins;

import android.content.Context;
import android.content.SharedPreferences;

public class SharedPrefsUtil {
    
    private static final String PREFS_NAME = "SystemUtilPrefs";
    
    public static void savePreference(Context context, String key, String value) {
        SharedPreferences sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sharedPreferences.edit();
        editor.putString(key, value);
        editor.apply();
    }
    
    public static String getPreference(Context context, String key) {
        SharedPreferences sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        return sharedPreferences.getString(key, "");
    }
}