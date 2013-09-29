//
//  PIController.h
//  iMITMProtect
//
//  Created by Cyril on 05/09/13.
//  Copyright (c) 2013 QuarksLab. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface PIController : NSViewController <NSTableViewDelegate, NSTableViewDataSource, NSWindowDelegate> {
@private

}

@property (assign) IBOutlet NSObject *delegate;

- (void) forceRefresh;

- (void) populateData;

- (NSInteger) numberOfRowsInTableView: (NSTableView *) aTableView;
- (id) tableView: (NSTableView *)aTableView objectValueForTableColumn: (NSTableColumn *)aTableColumn row:(NSInteger)rowIndex;

@property (nonatomic, strong) NSArray *data;
@property (nonatomic, strong) NSMutableArray *colNames;
@property (weak) IBOutlet NSTableView *tableView;

- (IBAction) refreshRequested: (id) sender;
- (IBAction) copySelection: (id)sender;
- (IBAction) selectAll: (id)sender;
@end
