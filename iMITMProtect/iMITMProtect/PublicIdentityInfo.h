//
//  PublicIdentityInfo.h
//  iMITMProtect
//
//  Created by Cyril on 06/09/13.
//  Copyright (c) 2013 QuarksLab. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface PublicIdentityInfo : NSObject

@property (strong) NSString* token;
@property (strong) NSString* identity;
@property (strong) NSString* pub_key;

@end
