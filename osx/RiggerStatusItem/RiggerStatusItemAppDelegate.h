//
//  RiggerStatusItemAppDelegate.h
//  RiggerStatusItem
//
//  Created by Wouter Wijngaards on 8/29/11.
//  Copyright 2011 NLnet Labs. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface RiggerStatusItemAppDelegate : NSObject <NSApplicationDelegate> {
    NSWindow *window;
}

@property (assign) IBOutlet NSWindow *window;

@end
