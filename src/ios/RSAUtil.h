#import <Foundation/Foundation.h>

@interface RSAUtil : NSObject

// RSA 加密方法
+ (NSString *)encryptWithRSA:(NSString *)plaintext publicKeyStr:(NSString *)publicKeyStr;

@end