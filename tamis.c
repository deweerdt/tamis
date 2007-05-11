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
			return -1;
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

int tamis_unprotect(struct tamis_memzone *mz)
{
	void *p = mz->mem - ((unsigned long)mz->mem % PAGE_SIZE);
	return mprotect(p, mz->len, PROT_READ | PROT_WRITE);
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
	//printf("restoring %p\n", eip);
	eip[0] = tamis_private.old_opcode;	
	exepage_protect(eip);

	ucontext->uc_mcontext.gregs[REG_EIP] = (int)eip;
	tamis_protect(tamis_private.to_protect_mem,
		      tamis_private.to_protect_len);
	return;
}

static struct tamis_memzone _mz[512];
static int imz = 0;

static void del_memzone(struct tamis_memzone *mz)
{
	memset(mz, 0, sizeof(*mz));
}
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
	int len;
	ucontext_t *ucontext = (ucontext_t *)stack;


	mz = find_memzone(info->si_addr);

	if (mz) {
		eip = (void *)ucontext->uc_mcontext.gregs[REG_EIP];
		len = insn_len(eip);
		if (len < 0) {
			printf("Unknown opcode %02x at %p\n", ((uint8_t*)eip)[0], eip);
			exit(0);
		}
		next_insn = eip + len;

		exepage_unprotect(next_insn);
		tamis_private.old_opcode = ((uint8_t *)next_insn)[0];
		//printf("setting %p\n", next_insn);
		((uint8_t *)next_insn)[0] = BREAK_INSN;
		exepage_protect(next_insn);

		ebp = (void**)ucontext->uc_mcontext.gregs[REG_EBP];
		tamis_private.to_protect_mem = mz->mem;
		tamis_private.to_protect_len = mz->len;
		tamis_unprotect(mz);

		if (mz_includes(info->si_addr, mz)) {
			/* */
		}
	} else {
		printf("not our sigsegv at %p\n", info->si_addr);
		while(1);
		exit(0);
	}
	return;
}

void tamis_unshare(void *p)
{
	struct tamis_memzone *mz;
	mz = find_memzone(p);
	if (!mz)
		return;
	tamis_unprotect(mz);
	del_memzone(mz);
}

void tamis_share(void *p, size_t len)
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

#define SIZE (sizeof(int)*126)
int main()
{
	int *ptr;
	int *ptr2;
	int *ptr3;
	int i, loops=10000;
	struct timeval tv1, tv2;

	if (tamis_init()) {
		perror("failed to init tamis");
		exit(0);
	}

	ptr = malloc(SIZE);
	ptr3 = malloc(4096);
	ptr2 = malloc(SIZE);

	tamis_share(ptr, SIZE);

	gettimeofday(&tv1);
	for (i=0; i < loops; i++) {
		ptr[i%(SIZE/sizeof(ptr[0]))] = 2;
	}
	gettimeofday(&tv2);
	printf("len: %d %d\n", tv2.tv_sec - tv1.tv_sec, tv2.tv_usec - tv1.tv_usec);

	tamis_unshare(ptr);

	gettimeofday(&tv1);
	for (i=0; i < loops; i++) {
		ptr2[i%(SIZE/sizeof(ptr[0]))] = 2;
	}
	gettimeofday(&tv2);
	printf("len: %d %d\n", tv2.tv_sec - tv1.tv_sec, tv2.tv_usec - tv1.tv_usec);

	free(ptr);
	free(ptr2);
	free(ptr3);
	puts("OK");
	return 1;
}
