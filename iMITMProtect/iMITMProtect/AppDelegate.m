//
//  AppDelegate.m
//  iMITMProtect
//
//  Created by Cyril on 05/09/13.
//  Copyright (c) 2013 QuarksLab. All rights reserved.
//

#import "AppDelegate.h"
#import "Injector.h"

@implementation AppDelegate

NSStatusItem *statusItem;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    // Insert code here to initialize your application
    NSStatusBar *statusBar = [NSStatusBar systemStatusBar];
    statusItem = [statusBar statusItemWithLength: NSVariableStatusItemLength];
    [statusItem setImage: [[NSBundle mainBundle] imageForResource: @"menubar"]];
    [statusItem setToolTip: @"Quarkslab's iMessage man-in-the-middle protection"];
    [statusItem setHighlightMode: YES];
    
    NSMenu *theMenu;
    theMenu = [[NSMenu alloc] initWithTitle: @""];
    [theMenu setAutoenablesItems: NO];
    NSMenuItem *tItem = nil;
    
    tItem = [theMenu addItemWithTitle: @"Public Identities" action: @selector(showPublicIdentities) keyEquivalent: @"p"];
    [tItem setKeyEquivalentModifierMask: NSCommandKeyMask];
    
    [theMenu addItem: [NSMenuItem separatorItem]];
    tItem = [theMenu addItemWithTitle: @"Quit" action: @selector(terminate:) keyEquivalent: @"q"];
    [tItem setKeyEquivalentModifierMask: NSCommandKeyMask];
    
    [statusItem setMenu: theMenu];
    
    // initializing controllers
    self.piController =  [[PIController alloc] initWithNibName:@"PublicIdentities" bundle: nil];;
    
    // Empty all previous notifications
    [[NSUserNotificationCenter defaultUserNotificationCenter] removeAllDeliveredNotifications];
    
    Injector *injector =[[Injector alloc] init];
    [injector start];
}

- (void) showPublicIdentities {
    [self.window makeKeyAndOrderFront: self];
    
    ProcessSerialNumber psn;
    if (noErr == GetCurrentProcess(&psn)) {
        SetFrontProcess(&psn);
    }
}

@end
