//
//  RiggerApp.h
//  RiggerStatusItem
//
//  Created by Wouter Wijngaards on 8/29/11.
//  Copyright 2011 NLnet Labs. All rights reserved.
//

#import <Cocoa/Cocoa.h>
struct cfg;

/* class that helps catch window close on the noweb window */
@interface NowebDelegate : NSObject {
}
-(BOOL)windowShouldClose:(NSWindow*)sender;
@end

/* class that helps catch window close on the update window */
@interface UpdateDelegate : NSObject {
}
-(BOOL)windowShouldClose:(NSWindow*)sender;
@end


@interface RiggerApp : NSObject {
	/* outlets connect to the interface */
	IBOutlet NSMenu* riggermenu;
	NSStatusItem* riggeritem;
	NSImage* icon;
	NSImage* icon_alert;
	IBOutlet NSWindow* resultwindow;
	IBOutlet NSTextView* resultpane;
	IBOutlet NSWindow* unsafewindow;
	IBOutlet NSTextField* unsafepane;
	IBOutlet NSWindow* hotsignwindow;
	IBOutlet NSWindow* nowebwindow;
	IBOutlet NSWindow* updatewindow;
	IBOutlet NSTextField* updatelabel;
	
@public
	/** if we have asked about disconnect or insecure */
	int unsafe_asked;
	/** if we should ask unsafe */
	int unsafe_should;
	/** if we have asked about noweb access */
	int noweb_asked;
	/** configuration */
	struct cfg* cfg;
}

/* IBAction to connect to the routine that takes actions after menu */
-(IBAction)Reprobe:(id)sender;
-(IBAction)ProbeResults:(id)sender;
-(IBAction)ProbeResultsOK:(id)sender;
-(IBAction)UnsafeInsecure:(id)sender;
-(IBAction)UnsafeDisconnect:(id)sender;
-(IBAction)HotspotSignon:(id)sender;
-(IBAction)HotsignOK:(id)sender;
-(IBAction)HotsignCancel:(id)sender;
-(IBAction)NowebLogin:(id)sender;
-(IBAction)NowebSkip:(id)sender;
-(IBAction)UpdateOK:(id)sender;
-(IBAction)UpdateCancel:(id)sender;
-(BOOL)windowShouldClose:(NSWindow*)sender;
-(void)SpawnFeed:(id)param;
-(void)PanelUpdateAlert;
-(void)PanelAlert;
-(void)PresentUnsafeDialog;
-(void)PanelAlertDanger;
-(void)PanelAlertSafe;
-(void)PresentNowebDialog;
-(void)PresentUpdateDialog:(char*)newversion;

@end
