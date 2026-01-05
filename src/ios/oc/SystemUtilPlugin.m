#import "SystemUtilPlugin.h"
#import "AESUtil.h"
#import "MD5Util.h"
#import "RSAUtil.h"
#import "StorageUtil.h"
#import "SM3Util.h"
#import "SM2Util.h"
#import <UIKit/UIKit.h>

@implementation SystemUtilPlugin {
    NSString *_accessToken;
    NSString *_prvKey;
    NSString *_decryptedS; // 存储解密后的s值
}

static NSString *const kKey = @""; // 这里应该是实际的密钥
static NSString *const kIV = @"";  // 这里应该是实际的IV
static NSString *const kEncryptedS = @""; // 这里应该是加密的s值
static NSString *const kEncryptedFS = @"";
static NSString *const kEncryptedPS = @"";

#pragma mark - 初始化方法

- (void)pluginInitialize {
    [super pluginInitialize];
    
    // 在初始化时直接解密s，后面直接使用_decryptedS
    if (kEncryptedS.length > 0 && kKey.length > 0 && kIV.length > 0) {
        @try {
            _decryptedS = [AESUtil decryptCBC:kEncryptedS key:kKey iv:kIV];
            NSLog(@"SystemUtilPlugin: s解密成功，长度: %lu", (unsigned long)_decryptedS.length);
        } @catch (NSException *exception) {
            NSLog(@"SystemUtilPlugin: s解密失败: %@", exception.reason);
            _decryptedS = @"";
        }
    } else {
        NSLog(@"SystemUtilPlugin: kEncryptedS、kKey或kIV为空，无法解密s");
    }
    
    [StorageUtil savePreference:@"fin1Key" value:kEncryptedFS];
    [StorageUtil savePreference:@"fac1Key" value:kEncryptedPS];
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
        NSString* fingerKey = [params objectForKey:@"fingerKey"] ?: @"";
        NSString* faceKey = [params objectForKey:@"faceKey"] ?: @"";
        
        if (fingerKey.length > 0) {
            NSString* encryptedPubKey = [AESUtil encryptCBC:fingerKey key:kKey iv:kIV];
            [StorageUtil savePreference:@"fin2Key" value:encryptedPubKey];
            
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        } else if (faceKey.length > 0) {
            NSString* encryptedPubKey = [AESUtil encryptCBC:faceKey key:kKey iv:kIV];
            [StorageUtil savePreference:@"fac2Key" value:encryptedPubKey];
            
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
            // 直接返回已经解密的s值
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK 
                                             messageAsString:_decryptedS ?: @""];
        } else if ([name isEqualToString:@"all"]) {
            NSMutableDictionary* resultDict = [NSMutableDictionary dictionary];
            
            resultDict[@"t"] = _accessToken ?: @"";
            resultDict[@"p"] = _prvKey ?: @"";
            // 直接使用已经解密的s值
            resultDict[@"s"] = _decryptedS ?: @"";
            
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK 
                                         messageAsDictionary:resultDict];
        } else if ([name isEqualToString:@"sign"]) {
            NSString* a1 = [params objectForKey:@"a1"] ?: @"";
            NSString* a2 = [params objectForKey:@"a2"] ?: @"";
            NSString* a3 = [params objectForKey:@"a3"] ?: @"";
            
            // 1. 使用SM3加密(a1 + a2 + a3 + t)
            NSString* m1 = [NSString stringWithFormat:@"%@%@%@", a1, a2, a3];
            
            if (_accessToken.length > 0) {
                m1 = [m1 stringByAppendingString:_accessToken];
            }
            
            NSLog(@"SM3输入: %@", m1);
            NSString* sm3Hash = [SM3Util sm3:m1];
            NSLog(@"SM3输出: %@", sm3Hash);
            
            // 2. 获取设备UUID
            NSString* deviceUUID = [[[UIDevice currentDevice] identifierForVendor] UUIDString];
            NSLog(@"设备UUID: %@", deviceUUID);
            
            // 3. 直接使用已经解密的s值作为SM2公钥
            NSString* sm2PublicKey = _decryptedS;
            NSLog(@"SM2公钥长度: %lu", (unsigned long)sm2PublicKey.length);
            
            // 4. 使用SM2加密(sm3Hash + deviceUuid)
            NSString* toBeEncrypted = [NSString stringWithFormat:@"%@%@", sm3Hash ?: @"", deviceUUID ?: @""];
            NSLog(@"SM2待加密数据: %@", toBeEncrypted);
            
            NSString* encryptedData = @"";
            
            if (sm2PublicKey.length > 0 && toBeEncrypted.length > 0) {
                encryptedData = [SM2Util encryptWithSM2:toBeEncrypted publicKeyStr:sm2PublicKey];
                NSLog(@"SM2加密结果长度: %lu", (unsigned long)encryptedData.length);
            }
            
            NSMutableDictionary* resultDict = [NSMutableDictionary dictionary];
            resultDict[@"b"] = encryptedData ?: @"";
            
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK 
                                         messageAsDictionary:resultDict];
        } else {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR 
                                              messageAsString:@"参数错误"];
        }
    } @catch (NSException *exception) {
        NSLog(@"SystemUtilPlugin异常: %@", exception);
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR 
                                          messageAsString:exception.reason ?: @"获取失败"];
    }
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

@end