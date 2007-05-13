/*
    tamis.c - tamis core code
    Copyright (C) 2007  Frederik Deweerdt <frederik.deweerdt@gmail.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <ucontext.h>
#include <execinfo.h>
#include <stdint.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/time.h>

#include "tamis.h"

#if 1
#define pr_debug(x, a...) do { \
			 	char __buf[4096]; \
				sprintf(__buf, x, ##a); \
				fprintf(stderr, "0x%x	%s", (int)pthread_self(), __buf); \
			  } while(0);
#else
#define pr_debug(...) do {} while(0)
#endif

static __thread struct tamis_tls tamis_private;

static int (*orig_pthread_mutex_lock)(pthread_mutex_t *mutex);
static int (*orig_pthread_mutex_unlock)(pthread_mutex_t *mutex);

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
	tamis_private.lock_level++;
	return orig_pthread_mutex_lock(mutex);
}
int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	tamis_private.lock_level--;
	return orig_pthread_mutex_unlock(mutex);
}

static int insn_len(uint8_t *opcode)
{
	switch (opcode[0]) {
		case 0xa3:
			return 5;
		case 0xc7:
			return 7;
		case 0x8b:
			return 2;
		default:
			fprintf(stderr, "unknown opcode 0x%02x\n", opcode[0]);
			return -1;
	}
}
static void __attribute__((unused)) dump_mem(void *mem, size_t len, size_t size)
{
	uint8_t *u8;
#if 0
	uint16_t *u16;
#endif
	uint32_t *u32;
	int i;
	char buf[4096] = "";
	char buf2[4096] = "";

	switch (size) {
		case 1:
			u8 = mem;
			for (i=0; i <= len / size; i++) {
				if (!(i%8))
					pr_debug("%02x ", u8[i]);
			}
			break;
		case 4:
			u32 = mem;
			for (i=0; i <= len / size; i++) {
				buf2[0] = '\0';
				sprintf(buf2, "%08x ", u32[i]);
				strcat(buf, buf2);
				if (!(i%8)) {
					pr_debug("%s\n", buf);
					buf[0] = '\0';
				}
			}
			break;
		default:
			pr_debug("Unhandled size %d\n", size);
	}
	pr_debug("\n");
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

static pthread_mutex_t tamis_lock = PTHREAD_MUTEX_INITIALIZER;

static void signal_trap(int signum, siginfo_t * info, void* stack)
{
	int8_t *eip;
	ucontext_t *ucontext = stack;

	eip = (int8_t *)ucontext->uc_mcontext.gregs[REG_EIP] - 1;

	exepage_unprotect(eip);
	pr_debug("restoring %p\n", eip);
	eip[0] = tamis_private.old_opcode;	
	exepage_protect(eip);

	ucontext->uc_mcontext.gregs[REG_EIP] = (int)eip;
	tamis_protect(tamis_private.to_protect_mem,
		      tamis_private.to_protect_len);

	/* locked in signal_segv */
	pthread_mutex_unlock(&tamis_lock);

	return;
}

/* 
 * TODO: the whole memzone handling sucks,
 * use something dynamic
 */
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
	pr_debug("find return null for %p\n", p);
	return NULL;
}

static void signal_segv(int signum, siginfo_t * info, void* stack)
{
	void **ebp = 0;
	void *eip = 0;
	void *next_insn = 0;
	struct tamis_memzone *mz;
	int len;
	ucontext_t *ucontext = stack;

	/* unlocked after signal_trap */
	pthread_mutex_lock(&tamis_lock);

	eip = (void *)ucontext->uc_mcontext.gregs[REG_EIP];
	pr_debug("sigsegv illegal access %p, eip %p\n", info->si_addr, eip);
	mz = find_memzone(info->si_addr);

	/*dump_mem(stack, 256, 4);*/
	if (mz) {
		
		len = insn_len(eip);
		if (len < 0) {
			fprintf(stderr, "Unknown opcode %02x at %p\n", ((uint8_t*)eip)[0], eip);
			exit(0);
		}
		/* TODO -1 or not ??? */
		next_insn = eip + len - 1;

		exepage_unprotect(next_insn);
		tamis_private.old_opcode = ((uint8_t *)next_insn)[0];
		pr_debug("setting %p 0x%02x\n", next_insn, ((uint8_t *)next_insn)[0]);
		((uint8_t *)next_insn)[0] = BREAK_INSN;
		exepage_protect(next_insn);

		ebp = (void**)ucontext->uc_mcontext.gregs[REG_EBP];
		tamis_private.to_protect_mem = mz->mem;
		tamis_private.to_protect_len = mz->len;
		tamis_unprotect(mz);

		if (mz_includes(info->si_addr, mz)) {
			/* even number of lockings == NOK */
			if ((tamis_private.lock_level & 1) ^ 1) {
				fprintf(stderr, "suspicious access from %p\n", eip);
			}
		}
	} else {
		fprintf(stderr, "not our sigsegv at %p\n", info->si_addr);
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

int tamis_share(void *p, size_t len)
{
	add_memzone(p, len);
	return tamis_protect(p, len);
}

#define HIJACK(a, x, y) if (!(orig_##x = dlsym(a , y))) {\
			   fprintf(stderr, "symbol %s() not found, exiting\n", #y);\
                	   exit(-1);\
                        }
int tamis_init()
{
	struct sigaction action;
	void *lib_handle = NULL;

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

	if ( (lib_handle = dlopen("libpthread.so", RTLD_NOW)) == NULL) {
		if ( (lib_handle = dlopen("libpthread.so.0", RTLD_NOW)) == NULL) {
			fprintf(stderr, "error loading libpthread!\n");
			return -1;
		}
	}

	HIJACK(lib_handle, pthread_mutex_lock, "pthread_mutex_lock");
	HIJACK(lib_handle, pthread_mutex_unlock, "pthread_mutex_unlock");

	return 0;
}


#define LOOPS 50
static int my_shared_var;
static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;

void *f_protected(void *arg)
{
	int i;
	for (i=0; i < LOOPS; i++) {
		pthread_mutex_lock(&m);
		my_shared_var = i;
		pthread_mutex_unlock(&m);
	}
	return NULL;
}
void *f_unprotected(void *arg)
{
	int i;
	for (i=0; i < LOOPS; i++) {
		my_shared_var = i;
	}
	return NULL;
}

void thread_test()
{
	pthread_t t1;
	pthread_t t2;

	tamis_share(&my_shared_var, sizeof(my_shared_var));
	pthread_create(&t1, NULL, f_protected, NULL);
	pthread_create(&t2, NULL, f_unprotected, NULL);
	pthread_join(t1, NULL);
	pthread_join(t2, NULL);
}

void *timing(void *arg)
{
	int *ptr;
	int *ptr2;
	int *ptr3;
	int i, loops=10000;
	struct timeval tv1, tv2;
	
#define SIZE (sizeof(int)*126)
	ptr = malloc(SIZE);
	ptr3 = malloc(4096);
	ptr2 = malloc(SIZE);

	tamis_share(ptr, SIZE);

	gettimeofday(&tv1, NULL);
	for (i=0; i < loops; i++) {
		//ptr[i%(SIZE/sizeof(ptr[0]))] = 2;
		ptr[0] = 2;
	}
	gettimeofday(&tv2, NULL);
	gettimeofday(&tv1, NULL);
	printf("with protection:: %lds %ldus\n", tv2.tv_sec - tv1.tv_sec, tv2.tv_usec - tv1.tv_usec);

	tamis_unshare(ptr);

	gettimeofday(&tv1, NULL);
	for (i=0; i < loops; i++) {
		ptr2[i%(SIZE/sizeof(ptr[0]))] = 2;
	}
	gettimeofday(&tv2, NULL);
	printf("without protection: %lds %ldus\n", tv2.tv_sec - tv1.tv_sec, tv2.tv_usec - tv1.tv_usec);

	free(ptr);
	free(ptr2);
	free(ptr3);
	puts("OK");
}

int main()
{
	pthread_t t;
	tamis_init();
	pthread_create(&t, NULL, timing, NULL);
	pthread_join(t, NULL);
	//thread_test();
	return 0;
}
