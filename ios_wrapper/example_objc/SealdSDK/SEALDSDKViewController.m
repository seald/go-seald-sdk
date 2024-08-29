//
//  SEALDSDKViewController.m
//  SealdSDK
//
//  Created by clement on 02/13/2023.
//  Copyright (c) 2023 Seald SAS. All rights reserved.
//

#import "SEALDSDKViewController.h"
#import "SEALDSDKAppDelegate.h"

@interface SEALDSDKViewController ()
@end

@implementation SEALDSDKViewController

- (void) viewDidLoad
{
    [super viewDidLoad];

    SEALDSDKAppDelegate* appDelegate = (SEALDSDKAppDelegate*)[[UIApplication sharedApplication] delegate];

    [appDelegate addObserver:self forKeyPath:@"testSsksTmrLabel" options:NSKeyValueObservingOptionNew context:nil];
    [appDelegate addObserver:self forKeyPath:@"testSsksPasswordLabel" options:NSKeyValueObservingOptionNew context:nil];
    [appDelegate addObserver:self forKeyPath:@"testSdkLabel" options:NSKeyValueObservingOptionNew context:nil];
    self.testSsksTmrLabel.text = [NSString stringWithFormat:@"test SSKS TMR: %@", appDelegate.testSsksTmrLabel];
    self.testSsksPasswordLabel.text = [NSString stringWithFormat:@"test SSKS Password: %@", appDelegate.testSsksPasswordLabel];;
    self.testSdkLabel.text = [NSString stringWithFormat:@"test SDK: %@", appDelegate.testSdkLabel];
}

- (void) observeValueForKeyPath:(NSString*)keyPath
                       ofObject:(id)object
                         change:(NSDictionary<NSKeyValueChangeKey,id>*)change
                        context:(void*)context
{
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString* newStatus = [change objectForKey:NSKeyValueChangeNewKey];
        if ([keyPath isEqualToString:@"testSsksTmrLabel"]) {
            self.testSsksTmrLabel.text = [NSString stringWithFormat:@"test SSKS TMR: %@", newStatus];
        } else if ([keyPath isEqualToString:@"testSsksPasswordLabel"]) {
            NSString* newStatus = [change objectForKey:NSKeyValueChangeNewKey];
            self.testSsksPasswordLabel.text = [NSString stringWithFormat:@"test SSKS Password: %@", newStatus];;
        } else if ([keyPath isEqualToString:@"testSdkLabel"]) {
            NSString* newStatus = [change objectForKey:NSKeyValueChangeNewKey];
            self.testSdkLabel.text = [NSString stringWithFormat:@"test SDK: %@", newStatus];
        }
    });
}

- (void) dealloc
{
    SEALDSDKAppDelegate* appDelegate = (SEALDSDKAppDelegate*)[[UIApplication sharedApplication] delegate];
    [appDelegate removeObserver:self forKeyPath:@"testSsksTmrLabel"];
    [appDelegate removeObserver:self forKeyPath:@"testSsksPasswordLabel"];
    [appDelegate removeObserver:self forKeyPath:@"testSdkLabel"];
}
@end
