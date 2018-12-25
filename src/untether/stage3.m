#include <stdint.h>

void where_it_all_starts(uint64_t id,void *(*write) (int fd,void * buf,uint64_t size)) {
	while (1) {}
	/*
	if (id != 0xdeadbeef) {} // handle error here
	char test[1024] = "Is this the real life?\nIs this just fantasy?\n";
	write(1,&test,sizeof(test));
	while(1){}
	*/
}
