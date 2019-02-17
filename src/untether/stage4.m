#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <Foundation/NSObjCRuntime.h>
#include <shared/jailbreak.h>

void sighandler(int signo) {
	LOG("recieved signal: %d",signo);
}

int main() {
	/*
	printf("I guess this is how it feels to run in C and with a normal cache, you can just call functions\n");
	int fd = open("/bootstrap/test/yowhatsup",O_WRONLY | O_CREAT);
	write(fd,"WEAREOUTHERE",13);
	while (1) {
		NSLog(@"YEHA\n");
	}
	*/
	for (int i = 0; i < 32; i++) {signal(i,sighandler);}
	jailbreak(JBOPT_POST_ONLY);
}
