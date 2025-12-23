#import "SystemUtilPlugin.h"
#import "AESUtil.h"
#import "MD5Util.h"
#import "RSAUtil.h"
#import "StorageUtil.h"
#import <UIKit/UIKit.h>

@implementation SystemUtilPlugin {
    NSString *_accessToken;
    NSString *_prvKey;
}

static NSString *const kKey = @"";
static NSString *const kIV = @"";
static NSString *const kEncryptedS = @"";
static NSString *const kEncryptedPS = @""; // 添加 PS 常量

#pragma mark - 初始化方法

- (void)pluginInitialize {
    [super pluginInitialize];
    
    // 初始化时保存 PS 到 UserDefaults
    [StorageUtil savePreference:@"pubKey" value:kEncryptedPS];
}

#pragma mark - 主要方法

- (void)putIn:(CDVInvokedUrlCommand*)command {
    CDVPluginResult* pluginResult = nil;
    
    @try {
        NSDictionary* params = [command.arguments objectAtIndex:0];
        
        if (params) {
            _accessToken = [params objectForKey:@"accessToken"] ?: @"";
            _prvKey = [params objectForKey:@"prvKey"] ?: @"";
            
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        } else {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR 
                                              messageAsString:@"参数错误"];
        }
    } @catch (NSException *exception) {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR 
                                          messageAsString:@"缓存数字信封失败"];
    }
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)putPub:(CDVInvokedUrlCommand*)command {
    CDVPluginResult* pluginResult = nil;
    
    @try {
        NSDictionary* params = [command.arguments objectAtIndex:0];
        NSString* pubKey = [params objectForKey:@"pubKey"] ?: @"";
        
        if (pubKey.length > 0) {
            NSString* encryptedPubKey = [AESUtil encryptCBC:pubKey key:kKey iv:kIV];
            [StorageUtil savePreference:@"pubKey" value:encryptedPubKey];
            
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        } else {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR 
                                              messageAsString:@"公钥不能为空"];
        }
    } @catch (NSException *exception) {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR 
                                          messageAsString:@"缓存指纹公钥失败"];
    }
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)putOut:(CDVInvokedUrlCommand*)command {
    CDVPluginResult* pluginResult = nil;
    
    @try {
        NSDictionary* params = [command.arguments objectAtIndex:0];
        NSString* name = [params objectForKey:@"name"] ?: @"";
        
        if ([name isEqualToString:@"t"]) {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK 
                                             messageAsString:_accessToken ?: @""];
        } else if ([name isEqualToString:@"p"]) {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK 
                                             messageAsString:_prvKey ?: @""];
        } else if ([name isEqualToString:@"s"]) {
            NSString* decryptedS = [AESUtil decryptCBC:kEncryptedS key:kKey iv:kIV];
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK 
                                             messageAsString:decryptedS ?: @""];
        } else if ([name isEqualToString:@"ps"]) {
            NSString* decryptedPS = [AESUtil decryptCBC:kEncryptedPS key:kKey iv:kIV];
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK 
                                             messageAsString:decryptedPS ?: @""];
        } else if ([name isEqualToString:@"all"]) {
            NSMutableDictionary* resultDict = [NSMutableDictionary dictionary];
            
            resultDict[@"t"] = _accessToken ?: @"";
            resultDict[@"p"] = _prvKey ?: @"";
            
            NSString* decryptedS = [AESUtil decryptCBC:kEncryptedS key:kKey iv:kIV];
            resultDict[@"s"] = decryptedS ?: @"";
            
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK 
                                         messageAsDictionary:resultDict];
        } else if ([name isEqualToString:@"sign"]) {
            NSString* a1 = [params objectForKey:@"a1"] ?: @"";
            NSString* a2 = [params objectForKey:@"a2"] ?: @"";
            NSString* a3 = [params objectForKey:@"a3"] ?: @"";
            
            NSString* m1 = [NSString stringWithFormat:@"%@%@%@", a1, a2, a3];
            NSString* m2 = @"";
            
            if (_accessToken.length > 0) {
                m1 = [m1 stringByAppendingString:_accessToken];
            }
            
            NSString* deviceUUID = [[[UIDevice currentDevice] identifierForVendor] UUIDString];
            if (deviceUUID.length > 0) {
                m2 = [m2 stringByAppendingString:deviceUUID];
            }
            
            NSString* md51 = @"";
            NSString* md52 = @"";
            
            if (m1.length > 0) {
                md51 = [MD5Util md5:m1];
            }
            
            if (m2.length > 0) {
                md52 = [MD5Util md5:m2];
            }
            
            NSString* md5Result = @"";
            
            if (md51.length > 0) {
                md5Result = [md5Result stringByAppendingString:md51];
            }
            
            if (md52.length > 0) {
                md5Result = [md5Result stringByAppendingString:md52];
            }
            
            NSMutableDictionary* resultDict = [NSMutableDictionary dictionary];
            resultDict[@"b"] = md5Result;
            
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK 
                                         messageAsDictionary:resultDict];
        } else {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR 
                                              messageAsString:@"参数错误"];
        }
    } @catch (NSException *exception) {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR 
                                          messageAsString:exception.reason ?: @"获取失败"];
    }
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)getPub:(CDVInvokedUrlCommand*)command {
    CDVPluginResult* pluginResult = nil;
    
    @try {
        NSDictionary* params = [command.arguments objectAtIndex:0];
        NSString* name = [params objectForKey:@"name"] ?: @"";
        
        if ([name isEqualToString:@"first"]) {
            NSString* decryptedS = [AESUtil decryptCBC:kEncryptedS key:kKey iv:kIV];
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK 
                                             messageAsString:decryptedS ?: @""];
        } else if ([name isEqualToString:@"secend"]) {
            NSString* encryptedPubKey = [StorageUtil getPreference:@"pubKey"];
            if (encryptedPubKey.length > 0) {
                NSString* decryptedPubKey = [AESUtil decryptCBC:encryptedPubKey key:kKey iv:kIV];
                pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK 
                                                 messageAsString:decryptedPubKey ?: @""];
            } else {
                pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK 
                                                 messageAsString:@""];
            }
        } else {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR 
                                              messageAsString:@"参数错误"];
        }
    } @catch (NSException *exception) {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR 
                                          messageAsString:exception.reason ?: @"获取失败"];
    }
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

@end