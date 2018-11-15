#import "CreditsVC.h"

@implementation CreditsVC

- (id)init
{
    id ret = [super initWithNibName:nil bundle:nil];
    self.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Credits" image:nil tag:1];
    return ret;
}

- (void)loadView
{
    [super loadView];
}

@end
