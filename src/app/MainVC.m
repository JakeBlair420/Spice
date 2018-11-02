#import "MainVC.h"
#include "jailbreak.h"

@implementation MainVC

- (id)init
{
    id ret = [super initWithNibName:nil bundle:nil];
    self.tabBarItem = [[UITabBarItem alloc] initWithTabBarSystemItem:UITabBarSystemItemFeatured tag:0];
    self.title = self.tabBarItem.title = @"Noot Noot";
    return ret;
}

- (void)loadView
{
    [super loadView];
    self.view.backgroundColor = [UIColor colorWithHue:0.0 saturation:0.0 brightness:0.2 alpha:1.0];

    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    btn.translatesAutoresizingMaskIntoConstraints = NO;
    [btn setTitle:@"Jailbreak" forState:UIControlStateNormal];
    [btn setTitleColor:[UIColor colorWithHue:0.0 saturation:0.0 brightness:1.0 alpha:1.0] forState:UIControlStateNormal];
    [btn setTitleColor:[UIColor colorWithHue:0.0 saturation:0.0 brightness:0.7 alpha:1.0] forState:UIControlStateHighlighted];
    btn.titleLabel.font = [UIFont systemFontOfSize:18];
    [btn addTarget:self action:@selector(actionJailbreak) forControlEvents:UIControlEventTouchUpInside];

    [self.view addSubview:btn];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:btn attribute:NSLayoutAttributeCenterX relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterX multiplier:1.0 constant:0.0]];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:btn attribute:NSLayoutAttributeCenterY relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterY multiplier:1.1 constant:0.0]];
}

- (void)actionJailbreak
{
    if(!jailbreak())
    {
        // TODO: popup
    }
}

@end
