//
//  main.m
//  RiggerStatusItem
//
//  Created by Wouter Wijngaards on 8/29/11.
//  Copyright 2011 NLnet Labs. All rights reserved.
//

#import <Cocoa/Cocoa.h>
char* test_config_file = NULL;

int main(int argc, char *argv[])
{
    if(argc > 2 && strcmp(argv[1], "-c") == 0) {
	test_config_file = argv[2];
	argv[2] = argv[0];
	argv += 2;
	argc -= 2;
    }
    return NSApplicationMain(argc,  (const char **) argv);
}
