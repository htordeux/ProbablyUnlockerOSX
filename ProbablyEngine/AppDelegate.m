//
//  AppDelegate.m
//  ProbablyEngine
//
//  Created by Ben Phelps on 7/28/13.
//  Copyright (c) 2013 BenPhelps.me. All rights reserved.
//

#import "AppDelegate.h"
#include <mach/mach.h>
#include <Security/Authorization.h>

// for 17399
#define offset32 0x7F0362
#define offset64 0x1007CE7DF

@implementation AppDelegate

- (void)dealloc
{
    [super dealloc];
}

// thanks PocketGnome
- (void)populateWowInstances{
    NSMutableArray *PIDs = [[NSMutableArray array] retain];
    
    // Lets find all available processes!
    ProcessSerialNumber pSN = {kNoProcess, kNoProcess};
    for(NSDictionary *processDict in [[NSWorkspace sharedWorkspace] launchedApplications]) {
        if( [[processDict objectForKey: @"NSApplicationBundleIdentifier"] isEqualToString: @"com.blizzard.worldofwarcraft"] ) {
            pSN.highLongOfPSN = [[processDict objectForKey: @"NSApplicationProcessSerialNumberHigh"] longValue];
            pSN.lowLongOfPSN  = [[processDict objectForKey: @"NSApplicationProcessSerialNumberLow"] longValue];
            
            pid_t wowPID = 0;
            OSStatus err = GetProcessPID(&pSN, &wowPID);
            
            if((err == noErr) && (wowPID > 0)) {
                [PIDs addObject:[NSNumber numberWithInt:wowPID]];
            }
        }
    }
    
    // Build our menu! I'm sure I could use bindings to do this another way, but I'm a n00b :(
    NSMenu *wowInstanceMenu = [[[NSMenu alloc] initWithTitle: @"Instances"] autorelease];
    NSMenuItem *wowInstanceItem;
    int tagToSelect = 0;
    
    // WoW isn't open then :(
    if ( [PIDs count] == 0 ){
        wowInstanceItem = [[NSMenuItem alloc] initWithTitle: @"Game is not open" action: nil keyEquivalent: @""];
        [wowInstanceItem setTag: 0];
        [wowInstanceItem setRepresentedObject: 0];
        [wowInstanceItem setIndentationLevel: 0];
        [wowInstanceMenu addItem: [wowInstanceItem autorelease]];
    }
    // We have some instances running!
    else{
        [wowInstancePopUpButton setEnabled:true];
        // Add all of them to the menu!
        for ( NSNumber *pid in PIDs ){
            wowInstanceItem = [[NSMenuItem alloc] initWithTitle: [NSString stringWithFormat: @"%@", pid] action: nil keyEquivalent: @""];
            [wowInstanceItem setTag: [pid intValue]];
            [wowInstanceItem setRepresentedObject: pid];
            [wowInstanceItem setIndentationLevel: 0];
            [wowInstanceMenu addItem: [wowInstanceItem autorelease]];
        }
        if ( _selectedPID != 0 ){
            tagToSelect = _selectedPID;
        }
        else{
            tagToSelect = [[PIDs objectAtIndex:0] intValue];
            _selectedPID = tagToSelect;
            [patchLua setEnabled:true];
        }
    }
    
    
    [wowInstancePopUpButton setMenu: wowInstanceMenu];
    [wowInstancePopUpButton selectItemWithTag: tagToSelect];
    
    _newPID = _selectedPID;
    [PIDs release];
}

- (IBAction) scanApplicationsAction:(id)sender {
    [self populateWowInstances];
}

- (void) displayNotice:(id)message {
    [statusText setStringValue:message];
}

- (IBAction) patchLuaAction:(id)sender {
    
    kern_return_t kern_return;
    mach_port_t task;
    
    [patchLua setEnabled:false];
    
    kern_return = task_for_pid(mach_task_self(), _selectedPID, &task);
    
    if (kern_return!=KERN_SUCCESS)
    {
        [self displayNotice:@"Permission Failure."];
        return;
    }
    
    int is64bit = 0;
    int validProcess = 0;
    unsigned char *buf;
    
    uint32_t sz;
    
    kern_return = vm_read(task, offset32, 4, (pointer_t*)&buf, &sz);
    if (kern_return != KERN_SUCCESS) {
        if (kern_return == KERN_INVALID_ADDRESS) {
            kern_return = vm_read(task, offset64, 4, (pointer_t*)&buf, &sz);
            if (kern_return != KERN_SUCCESS) {
                if (kern_return == KERN_INVALID_ADDRESS) {
                    [self displayNotice:@"Could not find offset."];
                }
                else {
                    [self displayNotice:@"Could not verify process memory."];
                    return;
                }
            }
            else {
                is64bit = 1;
            }
        }
        else {
            [self displayNotice:@"Could not verify process memory."];
            return;
        }
    }
    
    unsigned char patch[1] = {0xeb};
    
    // x64 5.4 = 116 109 131 255
    // x86 5.4 = 116 105 131 249
    
    // x86 17359 0x7F0312
    // x64 17359 0x1007CEC1F
    // x86 17371 0x7F0362
    // x64 17371 0x1007CE7DF
    
    int validate32[4] = {0x74, 0x69, 0x83, 0xf9};
    int validate64[4] = {0x74, 0x6d, 0x83, 0xff};
    
    int patched32[4] = {0xeb, 0x69, 0x83, 0xf9};
    int patched64[4] = {0xeb, 0x6d, 0x83, 0xff};
    
    
    if ( (buf[0] == patched32[0] && buf[1] == patched32[1] && buf[2] == patched32[2] && buf[3] == patched32[3])
        || (buf[0] == patched64[0] && buf[1] == patched64[1] && buf[2] == patched64[2] && buf[3] == patched64[3]) ) {
        [self displayNotice:@"Process already looks patched"];
        return;
    }
    
    if ( buf[0] == validate32[0] && buf[1] == validate32[1] && buf[2] == validate32[2] && buf[3] == validate32[3] ) {
        validProcess = 1;
        is64bit = 0;
    }
    else if ( buf[0] == validate64[0] && buf[1] == validate64[1] && buf[2] == validate64[2] && buf[3] == validate64[3] ) {
        validProcess = 1;
        is64bit = 1;
    }
    else {
        [self displayNotice:@"Could not verify offset."];
        return;
    }
    
    if (validProcess) {
        
        if (is64bit) {
            
            kern_return = vm_protect(task, offset64, 1, 0, (VM_PROT_ALL | VM_PROT_COPY | VM_PROT_READ) );
            if (kern_return!=KERN_SUCCESS)
            {
                [self displayNotice:@"Could not unlock process memory."];
                return;
            }
            
            kern_return = vm_write(task, offset64, (mach_vm_address_t)&patch, sizeof(patch));
            if (kern_return!=KERN_SUCCESS)
            {
                [self displayNotice:@"Could not write to process ."];
                return;
            }
            else {
                [self displayNotice:@"Patch Success!"];
            }
            
        }
        else {
            
            kern_return = vm_protect(task, offset32, 1, 0, (VM_PROT_ALL | VM_PROT_COPY | VM_PROT_READ) );
            if (kern_return!=KERN_SUCCESS)
            {
                [self displayNotice:@"Could not unlock process memory."];
                return;
            }
            
            kern_return = vm_write(task, offset32, (mach_vm_address_t)&patch, sizeof(patch));
            if (kern_return!=KERN_SUCCESS)
            {
                [self displayNotice:@"Could not write to process memory."];
                return;
            }
            else {
                [self displayNotice:@"Patch Success!"];
            }
        }
    }
    
    return;
}

- (IBAction) selectPIDAction:(id)sender {
    _newPID = [[sender title] intValue];
    if (_selectedPID != _newPID) {
        _selectedPID = _newPID;
        NSLog(@"Selected PID %i", _selectedPID);
        [patchLua setEnabled:true];
    }
}

- (void)fetchOffsets {
    
}


- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    [statusText setStringValue:[NSString stringWithFormat:@"Supporting Game Version: 5.4.0 (17399)"]];
    [scanApplications setEnabled:true];
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)theApplication {
    return YES;
}

@end
