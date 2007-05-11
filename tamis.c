#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <ucontext.h>
#include <execinfo.h>
#include <stdint.h>
#include <sys/mman.h>

#include "tamis.h"

static __thread struct tamis_tls tamis_private;

static int insn_len(uint8_t *opcode)
{
	switch (opcode[0]) {
		case 0xc7:
			return 6;
		case 0x8b:
			return 1;
		default:
			printf("unknown insn %02x\n", opcode[0]);
			exit(0);
	}
}
static void dump_mem(void *mem, size_t len, size_t size)
{
	uint8_t *u8;
	uint16_t *u16;
	uint32_t *u32;
	int i;

	switch (size) {
		case 1:
			u8 = mem;
			for (i=0; i < len / size; i++) {
				if (!(i%8))
					printf("%02x ", u8[i]);
			}
		default:
			printf("Unhandled len %d\n", size);
	}
	return;
}

int tamis_protect(void *mem, size_t len)
{
	void *p = mem - ((unsigned long)mem % PAGE_SIZE);
	return mprotect(p, len, PROT_NONE);
}

int tamis_unprotect(void *mem, size_t len)
{
	void *p = mem - ((unsigned long)mem % PAGE_SIZE);
	return mprotect(p, len, PROT_READ | PROT_WRITE);
}

static void exepage_protect(void *mem)
{
	void *p = mem - ((unsigned long)mem % PAGE_SIZE);
	mprotect(p, PAGE_SIZE, PROT_EXEC|PROT_READ);
}

static void exepage_unprotect(void *mem)
{
	void *p = mem - ((unsigned long)mem % PAGE_SIZE);
	mprotect(p, PAGE_SIZE, PROT_READ|PROT_WRITE);
}

static void signal_trap(int signum, siginfo_t * info, void* stack)
{
	int8_t *eip;
	ucontext_t *ucontext = (ucontext_t *)stack;

	eip = (int8_t *)ucontext->uc_mcontext.gregs[REG_EIP] - 1;

	exepage_unprotect(eip);
	eip[0] = tamis_private.old_opcode;	
	exepage_protect(eip);

	ucontext->uc_mcontext.gregs[REG_EIP] = (int)eip;
	tamis_protect(tamis_private.to_protect_mem,
		      tamis_private.to_protect_len);
	return;
}

static struct tamis_memzone _mz[512];
static int imz = 0;

static void add_memzone(void *p, size_t len)
{
	_mz[imz].mem = p;
	_mz[imz].page = p - ((unsigned long)p % PAGE_SIZE);
	_mz[imz++].len = len;
}
static inline int mz_includes(void *p, struct tamis_memzone *mz)
{
	return p >= mz->mem && p < (mz->mem + mz->len);
}

static inline struct tamis_memzone *find_memzone(void *p)
{
	int i;
	for (i=0; i < imz; i++) {
		if (mz_includes(p, &_mz[i]))
			return &_mz[i];
	}
	return NULL;
}
static void signal_segv(int signum, siginfo_t * info, void* stack)
{
    void **ebp = 0;
    void *eip = 0;
    void *next_insn = 0;
    struct tamis_memzone *mz;
    ucontext_t *ucontext = (ucontext_t *)stack;

    eip = (void *)ucontext->uc_mcontext.gregs[REG_EIP];
    next_insn = eip + insn_len(eip);

    exepage_unprotect(next_insn);
    tamis_private.old_opcode = ((uint8_t *)next_insn)[0];
    ((uint8_t *)next_insn)[0] = BREAK_INSN;
    exepage_protect(next_insn);

    ebp = (void**)ucontext->uc_mcontext.gregs[REG_EBP];

    mz = find_memzone(info->si_addr);

    if (mz && mz_includes(info->si_addr, mz)) {
	    tamis_private.to_protect_mem = mz->mem;
	    tamis_private.to_protect_len = mz->len;
	    tamis_unprotect(info->si_addr, SIZE);
    }
    return;
}

void tamis_shared(void *p, size_t len)
{
	add_memzone(p, len);
	tamis_protect(p, len);
}

int tamis_init()
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	action.sa_sigaction = signal_segv;
	action.sa_flags = SA_SIGINFO;
	if(sigaction(SIGSEGV, &action, NULL) < 0) {
		return -1;
	}

	memset(&action, 0, sizeof(action));
	action.sa_sigaction = signal_trap;
	action.sa_flags = SA_SIGINFO;
	if(sigaction(SIGTRAP, &action, NULL) < 0) {
		return -1;
	}
	return 0;
}

int main()
{
	int *ptr;
	int *ptr2;
	int i, loops=10000;
	struct timeval tv1, tv2;

	if (tamis_init()) {
		perror("failed to init tamis");
		exit(0);
	}

	ptr = malloc(SIZE);
	malloc(4096);
	ptr2 = malloc(SIZE);

	tamis_shared(ptr, SIZE);

	gettimeofday(&tv1);
	for (i=0; i < loops; i++) {
		ptr[0] = 2;
	}
	gettimeofday(&tv2);
	printf("len: %d %d\n", tv2.tv_sec - tv1.tv_sec, tv2.tv_usec - tv1.tv_usec);

	gettimeofday(&tv1);
	for (i=0; i < loops; i++) {
		ptr2[0] = 2;
	}
	gettimeofday(&tv2);
	printf("len: %d %d\n", tv2.tv_sec - tv1.tv_sec, tv2.tv_usec - tv1.tv_usec);

	free(ptr);
	free(ptr2);
	puts("OK");
	return 1;
}
