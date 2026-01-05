#import "SM2Util.h"
#import "GMObjC/GMObjC.h"
#import "RSAUtil.h"

@implementation SM2Util

+ (NSString *)encryptWithSM2:(NSString *)plaintext publicKeyStr:(NSString *)publicKeyStr {
    @try {
        if (plaintext.length == 0 || publicKeyStr.length == 0) {
            return @"";
        }
        
        // 尝试使用GMObjC的SM2实现
        [GMSm2Utils setEllipticCurveType:0]; // GMCurveType_sm2p256v1
        [GMSm2Utils setPublicKeyMode:0];     // GMKeyModeHex
        
        NSData *plainData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
        NSData *encryptedData = [GMSm2Utils encryptData:plainData publicKey:publicKeyStr];
        
        if (encryptedData) {
            NSString *encryptedBase64 = [encryptedData base64EncodedStringWithOptions:0];
            return encryptedBase64 ?: @"";
        }
        
        // 如果GMObjC失败，回退到RSA
        NSLog(@"SM2加密失败，回退到RSA");
        return [RSAUtil encryptWithRSA:plaintext publicKeyStr:publicKeyStr];
    } @catch (NSException *exception) {
        NSLog(@"SM2加密异常: %@", exception);
        // 异常情况下回退到RSA
        return [RSAUtil encryptWithRSA:plaintext publicKeyStr:publicKeyStr];
    }
}

@end