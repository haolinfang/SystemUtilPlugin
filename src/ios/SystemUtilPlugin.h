#import <Cordova/CDV.h>

@interface SystemUtilPlugin : CDVPlugin

- (void)putIn:(CDVInvokedUrlCommand*)command;
- (void)putPub:(CDVInvokedUrlCommand*)command;
- (void)putOut:(CDVInvokedUrlCommand*)command;
- (void)getPub:(CDVInvokedUrlCommand*)command;

@end