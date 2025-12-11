#import <Cordova/CDV.h>

@interface SystemUtilPlugin : CDVPlugin

- (void)putIn:(CDVInvokedUrlCommand*)command;
- (void)putOut:(CDVInvokedUrlCommand*)command;

@end