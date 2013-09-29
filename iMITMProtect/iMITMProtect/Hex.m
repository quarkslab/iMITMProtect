//
//  Hex.m
//  iMITMProtect
//
//  Created by Cyril on 06/09/13.
//  Copyright (c) 2013 QuarksLab. All rights reserved.
//

#import "Hex.h"

@implementation NSData (Hex)
- (NSString*) toHexString: (bool) withSpaces {
    NSMutableString *hexStr = [[NSMutableString alloc] init];
    unsigned char *chars = (unsigned char*) [self bytes];
    for (NSUInteger i = 0; i < [self length]; i++) {
        if (withSpaces && i != 0) [hexStr appendString: @" "];
        [hexStr appendFormat: @"%02x", chars[i]];
    }
    return hexStr;
}
@end

@implementation NSString (Hex)

@end
