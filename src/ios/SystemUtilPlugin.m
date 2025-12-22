#import "SystemUtilPlugin.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <UIKit/UIKit.h>

@implementation SystemUtilPlugin {
    NSString *_accessToken;
    NSString *_prvKey;
}

static NSString *const kKey = @"";
static NSString *const kIV = @"";
static NSString *const kEncryptedS = @"";
static NSString *const kPrefsName = @"SystemUtilPrefs";

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
            // 加密并存储到NSUserDefaults
            NSString* encryptedPubKey = [self encryptAESCBC:pubKey key:kKey iv:kIV];
            [[NSUserDefaults standardUserDefaults] setObject:encryptedPubKey forKey:@"pubKey"];
            [[NSUserDefaults standardUserDefaults] synchronize];
            
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
            NSString* decryptedS = [self decryptAESCBC:kEncryptedS key:kKey iv:kIV];
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK 
                                             messageAsString:decryptedS ?: @""];
        } else if ([name isEqualToString:@"all"]) {
            NSMutableDictionary* resultDict = [NSMutableDictionary dictionary];
            
            resultDict[@"t"] = _accessToken ?: @"";
            resultDict[@"p"] = _prvKey ?: @"";
            
            NSString* decryptedS = [self decryptAESCBC:kEncryptedS key:kKey iv:kIV];
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
                md51 = [self md5:m1];
            }
            
            if (m2.length > 0) {
                md52 = [self md5:m2];
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
            NSString* decryptedS = [self decryptAESCBC:kEncryptedS key:kKey iv:kIV];
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK 
                                             messageAsString:decryptedS ?: @""];
        } else if ([name isEqualToString:@"secend"]) {
            NSString* encryptedPubKey = [[NSUserDefaults standardUserDefaults] stringForKey:@"pubKey"];
            if (encryptedPubKey) {
                NSString* decryptedPubKey = [self decryptAESCBC:encryptedPubKey key:kKey iv:kIV];
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

#pragma mark - AES CBC 加密/解密方法

- (NSString*)encryptAESCBC:(NSString*)plaintext key:(NSString*)key iv:(NSString*)iv {
    @try {
        if (key.length == 0) {
            return nil;
        }
        
        NSData *plainData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
        NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
        NSData *ivData = [iv dataUsingEncoding:NSUTF8StringEncoding];
        
        // 确保IV长度为16字节
        if (ivData.length < 16) {
            NSMutableData *paddedIV = [ivData mutableCopy];
            [paddedIV increaseLengthBy:16 - ivData.length];
            ivData = paddedIV;
        } else if (ivData.length > 16) {
            ivData = [ivData subdataWithRange:NSMakeRange(0, 16)];
        }
        
        size_t bufferSize = plainData.length + kCCBlockSizeAES128;
        void *buffer = malloc(bufferSize);
        
        if (buffer == NULL) {
            return nil;
        }
        
        size_t numBytesEncrypted = 0;
        CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                              kCCAlgorithmAES,
                                              kCCOptionPKCS7Padding,
                                              keyData.bytes,
                                              kCCKeySizeAES128,
                                              ivData.bytes,
                                              plainData.bytes,
                                              plainData.length,
                                              buffer,
                                              bufferSize,
                                              &numBytesEncrypted);
        
        NSString *encryptedBase64 = nil;
        
        if (cryptStatus == kCCSuccess) {
            NSData *encryptedData = [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
            encryptedBase64 = [encryptedData base64EncodedStringWithOptions:0];
        } else {
            free(buffer);
            NSLog(@"AES加密失败，状态码: %d", cryptStatus);
            return nil;
        }
        
        free(buffer);
        return encryptedBase64;
        
    } @catch (NSException *exception) {
        NSLog(@"AES加密异常: %@", exception);
        return nil;
    }
}

- (NSString*)decryptAESCBC:(NSString*)encryptedBase64 key:(NSString*)key iv:(NSString*)iv {
    @try {
        if (key.length == 0) {
            return nil;
        }
        
        // 清理Base64字符串（移除换行符）
        NSString *cleanBase64 = [encryptedBase64 stringByReplacingOccurrencesOfString:@"\n" withString:@""];
        
        // Base64解码
        NSData *encryptedData = [[NSData alloc] initWithBase64EncodedString:cleanBase64 
                                                                   options:0];
        if (!encryptedData) {
            NSLog(@"Base64解码失败");
            return nil;
        }
        
        // 准备密钥和IV
        NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
        NSData *ivData = [iv dataUsingEncoding:NSUTF8StringEncoding];
        
        // 确保IV长度为16字节（AES块大小）
        if (ivData.length < 16) {
            NSMutableData *paddedIV = [ivData mutableCopy];
            [paddedIV increaseLengthBy:16 - ivData.length];
            ivData = paddedIV;
        } else if (ivData.length > 16) {
            ivData = [ivData subdataWithRange:NSMakeRange(0, 16)];
        }
        
        // 执行AES解密
        size_t bufferSize = encryptedData.length + kCCBlockSizeAES128;
        void *buffer = malloc(bufferSize);
        
        if (buffer == NULL) {
            return nil;
        }
        
        size_t numBytesDecrypted = 0;
        CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                              kCCAlgorithmAES,
                                              kCCOptionPKCS7Padding,
                                              keyData.bytes,
                                              kCCKeySizeAES128,
                                              ivData.bytes,
                                              encryptedData.bytes,
                                              encryptedData.length,
                                              buffer,
                                              bufferSize,
                                              &numBytesDecrypted);
        
        NSString *decryptedString = nil;
        
        if (cryptStatus == kCCSuccess) {
            NSData *decryptedData = [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
            decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
        } else {
            free(buffer);
            NSLog(@"AES解密失败，状态码: %d", cryptStatus);
            return nil;
        }
        
        free(buffer);
        return decryptedString;
        
    } @catch (NSException *exception) {
        NSLog(@"AES解密异常: %@", exception);
        return nil;
    }
}

#pragma mark - MD5 计算方法

- (NSString*)md5:(NSString*)input {
    const char *cStr = [input UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5(cStr, (CC_LONG)strlen(cStr), digest);
    
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", digest[i]];
    }
    
    return output;
}

@end