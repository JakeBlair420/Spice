#import "CreditsVC.h"

@implementation CreditsVC

- (id)init
{
    id ret = [super initWithNibName:nil bundle:nil];
    self.tabBarItem = [[UITabBarItem alloc] initWithTabBarSystemItem:UITabBarSystemItemBookmarks tag:1];
    self.title = self.tabBarItem.title = @"Credits";
    return ret;
}

- (void)loadView
{
    [super loadView];
}

@end
