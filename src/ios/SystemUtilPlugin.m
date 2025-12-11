#import "SystemUtilPlugin.h"
#import <CommonCrypto/CommonCryptor.h>

@implementation SystemUtilPlugin {
    NSString *_accessToken;
    NSString *_prvKey;
}

static NSString *const kKey = @"";
static NSString *const kIV = @"";
static NSString *const kEncryptedS = @"";

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

#pragma mark - AES CBC 解密方法

- (NSString*)decryptAESCBC:(NSString*)encryptedBase64 key:(NSString*)key iv:(NSString*)iv {
    @try {
        // 1. 清理Base64字符串（移除换行符）
        NSString *cleanBase64 = [encryptedBase64 stringByReplacingOccurrencesOfString:@"\n" withString:@""];
        
        // 2. Base64解码
        NSData *encryptedData = [[NSData alloc] initWithBase64EncodedString:cleanBase64 
                                                                   options:0];
        if (!encryptedData) {
            NSLog(@"Base64解码失败");
            return nil;
        }
        
        // 3. 准备密钥和IV
        NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
        NSData *ivData = [iv dataUsingEncoding:NSUTF8StringEncoding];
        
        // 4. 确保IV长度为16字节（AES块大小）
        if (ivData.length < 16) {
            NSMutableData *paddedIV = [ivData mutableCopy];
            [paddedIV increaseLengthBy:16 - ivData.length];
            ivData = paddedIV;
        } else if (ivData.length > 16) {
            ivData = [ivData subdataWithRange:NSMakeRange(0, 16)];
        }
        
        // 5. 执行AES解密
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

@end