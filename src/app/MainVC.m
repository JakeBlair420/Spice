#include <shared/common.h>
#include <shared/jailbreak.h>
#include <shared/utils.h>
#include <shared/sbx.h>

#import <CoreFoundation/CoreFoundation.h>

#import "MainVC.h"

@implementation MainVC

UIButton *jbButton;
bool hasJailbroken = false;

- (id)init
{
    LOG("pullup");

    id ret = [super initWithNibName:nil bundle:nil];
    self.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Jailbreak" image:nil tag:1];
    return ret;
}

- (void)loadView
{
    [super loadView];
    self.view.backgroundColor = [UIColor colorWithHue:0.0 saturation:0.0 brightness:0.2 alpha:1.0];

    jbButton = [UIButton buttonWithType:UIButtonTypeSystem];
    jbButton.translatesAutoresizingMaskIntoConstraints = NO;
    [jbButton setTitle:@"Jailbreak" forState:UIControlStateNormal];
    [jbButton setTitleColor:[UIColor colorWithHue:0.0 saturation:0.0 brightness:1.0 alpha:1.0] forState:UIControlStateNormal];
    [jbButton setTitleColor:[UIColor colorWithHue:0.0 saturation:0.0 brightness:0.7 alpha:1.0] forState:UIControlStateHighlighted];
    [jbButton setBackgroundColor:[UIColor colorWithRed:1.00 green:0.00 blue:0.00 alpha:1.0]];
    jbButton.titleEdgeInsets = UIEdgeInsetsMake(0, 2, 0, 2);
    jbButton.titleLabel.font = [UIFont systemFontOfSize:30];
    [jbButton addTarget:self action:@selector(actionJailbreak) forControlEvents:UIControlEventTouchUpInside];

    [self.view addSubview:jbButton];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:jbButton attribute:NSLayoutAttributeCenterX relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterX multiplier:1.0 constant:0.0]];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:jbButton attribute:NSLayoutAttributeCenterY relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterY multiplier:1.1 constant:0.0]];
}

- (void)actionJailbreak
{
    if (hasJailbroken)
    {
        respring();
        return;
    }

    [jbButton setHidden:YES];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^(void) {
        int ret = jailbreak(0);
        NSLog(@"jailbreak ret: %d", ret);

        if (ret != 0) {
            NSLog(@"jailbreak failed");
            
            dispatch_async(dispatch_get_main_queue(), ^{
                [self exploitFailed];
            });
            
            return;
        }
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self exploitSucceeded];
        });
    });
}

- (void)exploitSucceeded
{
    hasJailbroken = true;

    [jbButton setTitle:@"Respring" forState:UIControlStateNormal];
    [jbButton setHidden:NO];
}

- (void)exploitFailed
{

}

@end
