//
//  AppDelegate.h
//  iMITMProtect
//
//  Created by Cyril on 05/09/13.
//  Copyright (c) 2013 QuarksLab. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "PIController.h"

@interface AppDelegate : NSObject <NSApplicationDelegate>

@property (strong) PIController *piController;
@property (weak) IBOutlet NSWindow *window;

- (void) showPublicIdentities;

@end
