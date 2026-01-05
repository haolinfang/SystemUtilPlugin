#import <Foundation/Foundation.h>

@interface SM2Util : NSObject

+ (NSString *)encryptWithSM2:(NSString *)plaintext publicKeyStr:(NSString *)publicKeyStr;

@end