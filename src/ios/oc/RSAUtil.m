#import "RSAUtil.h"
#import <Security/Security.h>

@implementation RSAUtil

+ (NSString *)encryptWithRSA:(NSString *)plaintext publicKeyStr:(NSString *)publicKeyStr {
    @try {
        // 移除PEM格式的头部和尾部
        NSString *publicKeyPEM = publicKeyStr;
        publicKeyPEM = [publicKeyPEM stringByReplacingOccurrencesOfString:@"-----BEGIN PUBLIC KEY-----" withString:@""];
        publicKeyPEM = [publicKeyPEM stringByReplacingOccurrencesOfString:@"-----END PUBLIC KEY-----" withString:@""];
        publicKeyPEM = [publicKeyPEM stringByReplacingOccurrencesOfString:@"\n" withString:@""];
        publicKeyPEM = [publicKeyPEM stringByReplacingOccurrencesOfString:@" " withString:@""];
        
        // Base64解码
        NSData *publicKeyData = [[NSData alloc] initWithBase64EncodedString:publicKeyPEM options:0];
        if (!publicKeyData) {
            NSLog(@"公钥Base64解码失败");
            return nil;
        }
        
        // 创建公钥
        NSDictionary *keyAttributes = @{
            (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
            (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
            (__bridge id)kSecAttrKeySizeInBits: @2048
        };
        
        CFErrorRef error = NULL;
        SecKeyRef publicKey = SecKeyCreateWithData((__bridge CFDataRef)publicKeyData, 
                                                   (__bridge CFDictionaryRef)keyAttributes, 
                                                   &error);
        
        if (error) {
            NSError *err = (__bridge NSError *)error;
            NSLog(@"创建公钥失败: %@", err.localizedDescription);
            CFRelease(error);
            return nil;
        }
        
        if (!publicKey) {
            NSLog(@"创建公钥失败");
            return nil;
        }
        
        // 加密数据
        NSData *plainData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
        if (!plainData) {
            NSLog(@"明文数据转换失败");
            CFRelease(publicKey);
            return nil;
        }
        
        // 使用 kSecKeyAlgorithmRSAEncryptionPKCS1 算法
        SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSAEncryptionPKCS1;
        
        if (!SecKeyIsAlgorithmSupported(publicKey, kSecKeyOperationTypeEncrypt, algorithm)) {
            NSLog(@"算法不支持");
            CFRelease(publicKey);
            return nil;
        }
        
        CFErrorRef encryptError = NULL;
        CFDataRef encryptedData = SecKeyCreateEncryptedData(publicKey, 
                                                            algorithm, 
                                                            (__bridge CFDataRef)plainData, 
                                                            &encryptError);
        
        if (encryptError) {
            NSError *err = (__bridge NSError *)encryptError;
            NSLog(@"RSA加密失败: %@", err.localizedDescription);
            CFRelease(publicKey);
            CFRelease(encryptError);
            return nil;
        }
        
        if (!encryptedData) {
            NSLog(@"RSA加密失败，未返回数据");
            CFRelease(publicKey);
            return nil;
        }
        
        // 转换为Base64字符串
        NSData *encryptedNSData = (__bridge NSData *)encryptedData;
        NSString *encryptedBase64 = [encryptedNSData base64EncodedStringWithOptions:0];
        
        // 释放资源
        CFRelease(encryptedData);
        CFRelease(publicKey);
        
        return encryptedBase64;
        
    } @catch (NSException *exception) {
        NSLog(@"RSA加密异常: %@", exception);
        return nil;
    }
}

@end