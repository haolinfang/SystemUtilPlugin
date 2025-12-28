package com.plugin.keystore;

public class KeyStore {
    static {
        System.loadLibrary("keystore");
    }

    // Native方法声明
    public native String getStringS();
    public native String getFin1Key();
    public native String getFac1Key();
    public native String getAESKey();
    public native String getAESIV();
}