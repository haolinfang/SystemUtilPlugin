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

static NSString *const kKey = @"a9s8d7f6g5h4j3k2";
static NSString *const kIV = @"z1x2c3v4b5n6m7q8";
static NSString *const kEncryptedS = @"Cu34hcmWCXkHft5FmI2pP0SoekDRaj2woG//1Tj4vV0CR+OeCCj1ci3Y6Ln3UKPr2+KFQOfOykts8Bg1NNI/8PvCbKQUNMrn3u3IZNMP3YrlcnD5yJcJHmlwnMBZX6Ruw3KyznynpFJGwTlyJgiwrTRsNjASV5i5WQlwhcXECSgqKjN9Uug2aBbIfho73GQb";
static NSString *const kEncryptedFS = @"mEGnz+o7k9+gGeFqNvImvJiX5+wor5FK7LtD+1hUlJ5p6VLE3d/0uNymciQEoTUrTWlwxoqQT/Ogkg3zLtIlN8n5wlfCUuhzn4JFTPZXV/pVbX7nKcvffaGfbN4Z6IJteNktXRTzJvPeI+EKHM5vlqIn+NFfk9AUptm20Rtyb+hdc0Jkrrr05SRR4vJDy9RHU1LrWyh6DjybSFfdh9jH40iWhaBmlWYJMBiuQPnidpSyGEy5POUIA+nt6TBoEmtnPO6AxXnx4ZSo68l2oRiPVQQkZBL6LEvH7cxz6qMZ1Y/rXZQ7TzU7osswnp0CLkuZW1NsCdxP0VcUGNjs0LzTyOP0RrqtrmcGWiaggAKo3sA9TtOpu/YMflPWToIEh0eRBd6WIoc732KiKq65NJ8wIppr0wwGqz3mGpPV92xktQw9l4euaT4FujbxP5yiXylI9CyKbHEAU5aCYMb3rkvWTWgGB8CjSuaYGfH9x/NlX4Pll9dBgjQ6k6PHv8nTBypiMrAg1Z+iOnAcKeKU6O70sA==";
static NSString *const kEncryptedPS = @"mEGnz+o7k9+gGeFqNvImvJiX5+wor5FK7LtD+1hUlJ4zjCzJknjy4dDnZLawGRqA2OnppD9qLsRlPMwsIab2Nm7wFXuCROXov/taWtK94wOU2ckosa5H7jfvHxo/hIuHTPh39oFd3EaL4auM+ePx0cJkWA1H0Jg+Zf+bpp8Amf9f/66XW6qzKekKlhEgmCt3mZbqbPeP84THxcXaYb0Dg13XBrVK9QE5MIFqD9wx/poOb698M0vo/Pfax1hljJm57ZgD2ScVJp96ES+3NrHeNc8noCCvn71iSnwFEgsuHFzLHKSljQsbZqafMLzkmT5Xze9TCS2tKCU3XVRmL8pYo37GoWTfCbCwv3diCaJA+VgaKKX7Z4tpqS5vfxs0wHohjILIWcQeAtbhViVFAWQhlqCPun0pD/OUVWnrOQPswFjtIma8Y2bWTd93HDC2/uCRsObGSiASXjgJUJ3NTcNgK1v6SmzFocR1NoXQtv8r2DLK4rfWlZSixFQW5yCtK3yGlgRTtGDzkPHzznDyQq2mbQ==";

#pragma mark - 初始化方法

- (void)pluginInitialize {
    [super pluginInitialize];
    
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
            NSString* decryptedS = [AESUtil decryptCBC:kEncryptedS key:kKey iv:kIV];
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK 
                                             messageAsString:decryptedS ?: @""];
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

@end