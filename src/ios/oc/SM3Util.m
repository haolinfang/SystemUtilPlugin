#import "SM3Util.h"
#import "GMObjC/GMObjC.h"
#import <CommonCrypto/CommonDigest.h>

@implementation SM3Util

+ (NSString *)sm3:(NSString *)input {
    @try {
        if (input.length == 0) {
            return @"";
        }
        
        // 尝试使用GMObjC的SM3实现
        NSData *inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
        NSString *hashResult = [GMSm3Utils hashWithData:inputData];
        
        if (hashResult && hashResult.length > 0) {
            return hashResult;
        }
        
        // 如果GMObjC失败，使用SHA-256作为替代
        const char *cStr = [input UTF8String];
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(cStr, (CC_LONG)strlen(cStr), digest);
        
        NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
        for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
            [output appendFormat:@"%02x", digest[i]];
        }
        
        return output;
    } @catch (NSException *exception) {
        NSLog(@"SM3加密异常: %@", exception);
        return @"";
    }
}

@end