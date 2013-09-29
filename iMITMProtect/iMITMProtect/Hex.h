//
//  Hex.h
//  iMITMProtect
//
//  Created by Cyril on 06/09/13.
//  Copyright (c) 2013 QuarksLab. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (Hex)
- (NSString*) toHexString: (bool) withSpaces;
@end

@interface NSString (Hex)

@end