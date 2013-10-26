//
//  main.m
//  ProbablyEngine
//
//  Created by Ben Phelps on 7/28/13.
//  Copyright (c) 2013 BenPhelps.me. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <Foundation/foundation.h>
#import <SecurityFoundation/SFAuthorization.h>
#import <Security/AuthorizationTags.h>
#include <sys/stat.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <pwd.h>

int main(int argc, char *argv[])
{
    return NSApplicationMain(argc, (const char **)argv);
}