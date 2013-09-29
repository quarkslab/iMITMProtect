//
//  PIController.m
//  iMITMProtect
//
//  Created by Cyril on 05/09/13.
//  Copyright (c) 2013 QuarksLab. All rights reserved.
//

#import "PIController.h"
#import "Base64.h"
#import "Hex.h"
#import "PublicIdentityInfo.h"

#include <CommonCrypto/CommonDigest.h>
#include <sqlite3.h>
#include <pwd.h>

@implementation PIController

- (id) initWithNibName: (NSString *)nibNameOrNil bundle: (NSBundle *)nibBundleOrNil {
    self = [super initWithNibName: nibNameOrNil bundle: nibBundleOrNil];
    if (self) {
        _data = nil;
        _colNames = nil;
    }
    return self;
}

NSString *current_user_home() {
    struct passwd *pw = getpwuid(getuid());
    assert(pw);
    return [NSString stringWithUTF8String: pw->pw_dir];
}

static int select_callback(void *param, int argc, char **argv, char **azColName){
    PIController *ref = (__bridge PIController*) param;
    if (ref.data == nil) ref.data = [[NSMutableArray alloc] init];
    if (ref.colNames == nil) {
        ref.colNames = [[NSMutableArray alloc] init];
        for (int i = 0; i < argc; i++) {
            [ref.colNames addObject: [NSString stringWithUTF8String: azColName[i]]];
        }
    }
    PublicIdentityInfo *info = [[PublicIdentityInfo alloc] init];
    for (int i = 0; i < argc; i++) {
        NSString *colName = [ref.colNames objectAtIndex: i];
        NSString *value = [ref adaptValue: [NSString stringWithUTF8String: argv[i]] colName: colName];
        [info setValue: value forKey: colName];
        
    }
    [(NSMutableArray*) ref.data addObject: info];
    return 0;
}

- (void) populateData {
    sqlite3 *db = NULL;
    char* error = NULL;
    char *sql = NULL;
    NSError *oerror = NULL;
    NSString* dbDir = [NSString stringWithFormat: @"%@/%@", current_user_home(), @DB_DIR_REL];
    NSString* dbPath = [NSString stringWithFormat: @"%@/%@", current_user_home(), @DB_PATH_REL];
    
    NSFileManager* fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath: dbDir] && ![fm createDirectoryAtPath: dbDir
                                        withIntermediateDirectories: YES
                                                         attributes: nil
                                                              error: &oerror]) {
        NSLog(@"%s: failed to create directory: %s. error: %s", APP_NAME, [dbDir UTF8String], [[oerror localizedDescription] cStringUsingEncoding: NSASCIIStringEncoding]);
        goto end;
    }
    
    if (sqlite3_open([dbPath UTF8String], &db) != SQLITE_OK) {
        NSLog(@"%s: failed to connect to sqlite database %s", APP_NAME, [dbPath UTF8String]);
        goto end;
    }
    
    _data = nil;
    _colNames = nil;
    if (sqlite3_exec(db, "SELECT * FROM pub_keys", select_callback, (__bridge void*) self, &error) != SQLITE_OK) {
        NSLog(@"%s: failed to query table: %s", APP_NAME, error);
        goto end;
    }
    
end:
    if (sql != NULL) sqlite3_free(sql);
    if (db != NULL) sqlite3_close(db);
}

- (void) forceRefresh {
    [self populateData];
    NSMutableArray *sortDescriptors = [[NSMutableArray alloc] init];
    [sortDescriptors addObject: [[NSSortDescriptor alloc] initWithKey: @"identity" ascending: YES]];
    [sortDescriptors addObject: [[NSSortDescriptor alloc] initWithKey: @"token" ascending: YES]];
    _data = [_data sortedArrayUsingDescriptors: sortDescriptors];
    _tableView.sortDescriptors = sortDescriptors;
    [_tableView reloadData];
}

- (NSInteger) numberOfRowsInTableView: (NSTableView *) aTableView {
    return [_data count];
}

- (NSString*) adaptValue: (NSString*) value colName: (NSString*) colName {
    if ([colName isEqualToString: @"identity"]) {
        value = [[value componentsSeparatedByString: @":"] objectAtIndex: 1];
    } else if ([colName isEqualToString: @"token"]) {
        NSData *bytes = [NSData dataWithBase64EncodedString: value];
        value = [bytes toHexString: false];
    } else if ([colName isEqualToString: @"pub_key"]) {
        unsigned char digest[CC_SHA1_DIGEST_LENGTH];
        NSData *bytes = [NSData dataWithBase64EncodedString: value];
        if (CC_SHA1(bytes.bytes, (unsigned int) bytes.length, digest)) {
            NSData *sha1 = [NSData dataWithBytes: digest length: CC_SHA1_DIGEST_LENGTH];
            value = [sha1 toHexString: false];
        }
    }
    return value;
}

- (id) tableView: (NSTableView *)aTableView objectValueForTableColumn: (NSTableColumn *)aTableColumn row:(NSInteger)rowIndex {
    NSString *colName = aTableColumn.identifier;
    PublicIdentityInfo *info = [_data objectAtIndex: rowIndex];
    return [info valueForKey: colName];
}

- (void) refreshRequested: (id)sender {
    [self forceRefresh];
}

- (void) tableView: (NSTableView *)tableView sortDescriptorsDidChange: (NSArray *)oldDescriptors {
    _data = [_data sortedArrayUsingDescriptors: tableView.sortDescriptors];
    [tableView reloadData];
}

- (void) windowDidBecomeKey: (NSNotification *)notification {
    [self forceRefresh];
}

- (IBAction) selectAll: (id)sender {
    NSIndexSet *all = [NSIndexSet indexSetWithIndexesInRange: NSMakeRange(0, [_tableView numberOfRows])];
    [_tableView selectRowIndexes: all byExtendingSelection: YES];
}

- (IBAction) copySelection: (id)sender {
    NSMutableString *text = [[NSMutableString alloc] init];
    NSIndexSet* rowIndexes = [_tableView selectedRowIndexes];
    NSUInteger index = [rowIndexes firstIndex];
    while (index != NSNotFound) {
        PublicIdentityInfo *info = [_data objectAtIndex: index];
        NSString* line = [NSString stringWithFormat: @"%@ %@ %@", info.identity, info.token, info.pub_key];
        [text appendFormat: @"%@\n", line];
        index = [rowIndexes indexGreaterThanIndex: index];
    }

    NSPasteboard *pasteBoard = [NSPasteboard generalPasteboard];
    [pasteBoard declareTypes: [NSArray arrayWithObject: NSStringPboardType] owner:nil];
    [pasteBoard setString: text forType: NSStringPboardType];
}

@end
