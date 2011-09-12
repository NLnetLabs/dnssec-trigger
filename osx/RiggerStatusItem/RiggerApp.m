//
//  RiggerApp.m
//  RiggerStatusItem
//
//  Created by Wouter Wijngaards on 8/29/11.
//  Copyright 2011 NLnet Labs. All rights reserved.
//
#include "config.h"
#include "cfg.h"
#include "log.h"
#include "osxattach.h"
#import "RiggerApp.h"

extern char* test_config_file;

/** basically these are the commandline arguments to PanelAlert */
struct alertinfo {
	NSLock* lock;
	int last_insecure;
	int now_insecure;
	int dark;
	int cache;
	int auth;
	int disconn;
} alertinfo;

static RiggerApp* mainapp = NULL;

static void cleanup(void)
{
	[mainapp dealloc];
}

@implementation RiggerApp

-(void)
awakeFromNib
{
	char* cfgfile = CONFIGFILE;
	if(test_config_file)
		cfgfile = test_config_file;
	
	/* Setup the status icon in the tray */
	riggeritem = [[[NSStatusBar	systemStatusBar]
				   statusItemWithLength:NSSquareStatusItemLength] retain];
	NSBundle* bundle = [NSBundle mainBundle];
	/* Note that the icon images are 18x18px in size and are png with
	 * transparency.  This makes the tray icon work on OSX.  Other
	 * sizes do not work. */
	icon = [[NSImage alloc] initWithContentsOfFile:
			[bundle pathForResource:@"status-icon" ofType:@"png"]];
	icon_alert = [[NSImage alloc] initWithContentsOfFile:
				  [bundle pathForResource:@"status-icon-alert" ofType:@"png"]];
	[riggeritem setImage:icon];
	/* [riggeritem setAlternateImage:icon_alert]; this would be the highlight image but
	 * we use the builtin highlight code that uses the alpha channel in the icon */
	[riggeritem setMenu:riggermenu];
	[riggeritem setToolTip:@"dnssec-trigger"];
	/* highlight the icon when the statusmenu is shown */
	[riggeritem setHighlightMode:YES];
	
	/* Init */
	mainapp = self;
	unsafe_asked = 0;
	memset(&alertinfo, 0, sizeof(alertinfo));
	alertinfo.lock = [NSLock alloc];
	log_ident_set("dnssec-trigger-panel-osx");
	log_init(NULL, 0, NULL);
	ERR_load_crypto_strings();
	ERR_load_SSL_strings();
	OpenSSL_add_all_algorithms();
	(void)SSL_library_init();
	
	/* Read config */
	cfg = cfg_create(cfgfile);
	if(!cfg)
		fatal_exit("cannot read config file %s", cfgfile);

	/* spawn the feed thread */
	feed = (struct feed*)calloc(1, sizeof(*feed));
	if(!feed) fatal_exit("out of memory");
	feed->lock = [NSLock alloc];
	atexit(&cleanup);
	[NSThread detachNewThreadSelector:@selector(SpawnFeed:)
							 toTarget:self withObject:nil];
}

-(void)
dealloc
{
	printf("dealloc routine\n");
	attach_stop();
	[feed->lock release];
	free(feed);
	[alertinfo.lock release];
	[icon release];
	[icon_alert release];
	[super dealloc];
}

-(void)SpawnFeed:(id)param
{
	attach_start(cfg);
}

-(IBAction)Reprobe:(id)sender
{
	NSLog(@"Reprobe");
	attach_send_reprobe();
}

void append_txt(NSTextView* pane, char* str)
{
	NSRange range;
	range.location = [[pane textStorage] length];
	range.length = 0;
	NSString* s = [NSString stringWithUTF8String:str];
	[pane replaceCharactersInRange: range withString: s];
	/* because the string is allocated with convenience function
	 * no need to [s release]. */
}

-(IBAction)ProbeResults:(id)sender
{
	NSLog(@"ProbeResults");
	/* this is to help us bring a window to the front
	 * from the hidden app */
	[NSApp activateIgnoringOtherApps:YES];
	[resultpane setEditable:YES];
	NSRange range;
	range.location = 0;
	range.length = [[resultpane textStorage] length];
	struct strlist* p = feed->results;
	[resultpane replaceCharactersInRange: range
		withString:@"results from probe "];
	if(p && strncmp(p->str, "at ", 3) == 0) {
		append_txt(resultpane, p->str);
		p=p->next;
	}
	append_txt(resultpane, "\n\n");		

	[feed->lock lock];
	if(!feed->connected) {
		append_txt(resultpane, "error: ");
		append_txt(resultpane, feed->connect_reason);
		append_txt(resultpane, "\n");		
	}
	for(; p; p=p->next) {
		if(!p->next) {
			/* last line */
			append_txt(resultpane, "\n");
			if(strstr(p->str, "cache"))
				append_txt(resultpane,
						   "DNSSEC results fetched from (DHCP) cache(s)\n");
			else if(strstr(p->str, "auth"))
				append_txt(resultpane,
						   "DNSSEC results fetched direct from authorities\n");
			else if(strstr(p->str, "disconnected"))
				append_txt(resultpane,
						   "The network seems to be disconnected. A local cache of DNS\n"
						   "results is used, but no queries are made.\n");
			else if(strstr(p->str, "dark") && !strstr(p->str, "insecure"))
				append_txt(resultpane, 
						   "A local cache of DNS results is used but no queries\n"
						   "are made, because DNSSEC is intercepted on this network.\n"
						   "(DNS is stopped)\n");
			else append_txt(resultpane,
							"DNS queries are sent to INSECURE servers.\n"
							"Please, be careful out there.\n");
		} else {
			append_txt(resultpane, p->str);
			append_txt(resultpane, "\n");
		}
	}
	[feed->lock unlock];
	
	[resultpane setEditable:NO];
	[resultpane setSelectable:YES];
	[resultwindow orderFront:sender];
}

-(IBAction)ProbeResultsOK:(id)sender
{
	NSLog(@"ProbeResultsOK");
	[resultwindow orderOut:sender];
}

-(IBAction)UnsafeInsecure:(id)sender
{
	NSLog(@"Unsafe:Insecure");
	[unsafewindow orderOut:sender];
	unsafe_asked = 1;
	attach_send_insecure(1);
}

-(IBAction)UnsafeDisconnect:(id)sender
{
	NSLog(@"Unsafe:Disconnect");
	[unsafewindow orderOut:sender];
	unsafe_asked = 1;
	attach_send_insecure(0);
}

-(BOOL)windowShouldClose:(NSWindow*)sender
{
	NSLog(@"unsafeclose handler");
	/* like pressing disconnect */
	unsafe_asked = 1;
	attach_send_insecure(0);
	return YES;
}

-(void)PresentUnsafeDialog
{
	[unsafewindow center];
	[unsafewindow deminiaturize:self];
	[unsafewindow orderFront:self];
}

-(void)PanelAlertDanger
{
	[riggeritem setImage:icon_alert];
}

-(void)PanelAlertSafe
{
	[riggeritem setImage:icon];
}

-(void)PanelAlert
{
	NSString* tt;
	int do_danger = 0, do_safe = 0, do_ask = 0;
	NSLog(@"PanelAlert function");
	[alertinfo.lock lock];
	if(alertinfo.now_insecure)
		tt = @"DNS DANGER";
	else if(alertinfo.dark)
		tt = @"DNS stopped";
	else if(alertinfo.cache)
		tt = @"DNSSEC via cache";
	else if(alertinfo.disconn)
		tt = @"network disconnected";
	else tt = @"DNSSEC via authorities";
	if(!alertinfo.dark)
		unsafe_asked = 0;
	if(!alertinfo.last_insecure && alertinfo.now_insecure) {
		do_danger = 1;
	} else if(alertinfo.last_insecure && !alertinfo.now_insecure) {
		do_safe = 1;
	}
	if(!alertinfo.now_insecure && alertinfo.dark && !unsafe_asked) {
		do_ask = 1;
	}
	[alertinfo.lock unlock];

	[riggeritem setToolTip:tt];
	if(do_danger)
		[self PanelAlertDanger];
	if(do_safe)
		[self PanelAlertSafe];
	if(do_ask)
		[self PresentUnsafeDialog];
}

void panel_alert_state(int last_insecure, int now_insecure, int dark,
					   int cache, int auth, int disconn)
{
	/* store parameters in threadsafe manner */
	[alertinfo.lock lock];
	alertinfo.last_insecure = last_insecure;
	alertinfo.now_insecure = now_insecure;
	alertinfo.dark = dark;
	alertinfo.cache = cache;
	alertinfo.auth = auth;
	alertinfo.disconn = disconn;
	[alertinfo.lock unlock];
	printf("panel alert state in attach\n");
	[mainapp performSelectorOnMainThread:@selector(PanelAlert)
							  withObject:nil waitUntilDone:NO];
}

@end
