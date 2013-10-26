//
//  AppDelegate.h
//  ProbablyEngine
//
//  Created by Ben Phelps on 7/28/13.
//  Copyright (c) 2013 BenPhelps.me. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#include <mach/mach.h>
#include <Security/Authorization.h>

@interface AppDelegate : NSObject <NSApplicationDelegate> {
    int _selectedPID;
    NSString *_offsetValue;
    NSString *_memoryValue;
    NSString *_gameVersion;
    int _newPID;
    IBOutlet NSPopUpButton *wowInstancePopUpButton;
    IBOutlet NSButton *scanApplications;
    IBOutlet NSButton *patchLua;
    IBOutlet NSTextField *statusText;
}

- (void) fetchOffsets;
- (IBAction) scanApplicationsAction:(id)sender;
- (IBAction) selectPIDAction:(id)sender;
- (IBAction) patchLuaAction:(id)sender;

@property (assign) IBOutlet NSWindow *window;

@end

