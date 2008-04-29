/*
    tamis.c - tamis core code
    Copyright (C) 2007, 2008  Frederik Deweerdt <frederik.deweerdt@gmail.com>

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

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <memory.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <ucontext.h>

#include "tamis.h"

#if 0
#define pr_debug(x, a...) do { \
			 	char __buf[4096]; \
				sprintf(__buf, x, ##a); \
				fprintf(stderr, "tid:0x%x\t%s", (int)pthread_self(), __buf); \
			  } while(0);
#else
#define pr_debug(...) do {} while(0)
#endif

static __thread struct tamis_private tamis_priv;
/* Serializes the accesses to the SIGSEGV/SIGTRAP code */
static __tamis pthread_mutex_t tamis_lock = PTHREAD_MUTEX_INITIALIZER;
static __tamis struct tamis_memzone _mz[512];
static __tamis int imz = 0;


/* returns the length of the opcode, opcode[0] included */
static int insn_len(uint8_t *opcode)
{
	switch (opcode[0]) {
		case 0xa1:
			return 5;
		case 0xa3:
			return 5;
		case 0xc7: /* takes an arg */
			switch(opcode[1]) {
			case 0x00:
				return 6;
			case 0x04:
				return 7;
			case 0x05:
				return 10;
			case 0x44:
				return 8;
			default:
				fprintf(stderr, "Unknown opcode 0xc7 %d\n", opcode[1]);
				assert(0);
			}
		case 0x8b:
			return 2;
		case 0x89:
			switch(opcode[1]) {
			case 0x04:
				return 3;
			default:
				return 2;
			}
		case 0xa5:
			return 1;
		case 0xf3:
			return 1;
		default:
			fprintf(stderr, "Unknown opcode 0x%02x\n", opcode[0]);
			assert(0);
	}
}

/*
 * mprotect wrappers for common tasks
 */
static int protect(void *mem, size_t len)
{
	void *p = mem - ((unsigned long)mem % PAGE_SIZE);
	return mprotect(p, len, PROT_NONE);
}

static int unprotect(struct tamis_memzone *mz)
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

/*
 * TODO: the whole memzone handling sucks,
 * use something dynamic
 */
static void del_memzone(struct tamis_memzone *mz)
{
	memset(mz, 0, sizeof(*mz));
}
static struct tamis_memzone *add_memzone(void *p, size_t len)
{
	struct tamis_memzone *mz = &_mz[imz];
	_mz[imz].mem = p;
	_mz[imz].page = p - ((unsigned long)p % PAGE_SIZE);
	_mz[imz++].len = len;

	return mz;
}
static inline int mz_includes(void *p, struct tamis_memzone *mz)
{
	return p >= mz->mem && p < (mz->mem + mz->len);
}

static struct tamis_memzone *find_memzone(void *p)
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
	void **ebp;
	void *eip;
	void *next_insn;
	struct tamis_memzone *mz;
	int len, ret;
	ucontext_t *ucontext = stack;

	/* unlocked after signal_trap */
	ret = pthread_mutex_lock(&tamis_lock);
	assert(ret == 0);

	eip = (void *)ucontext->uc_mcontext.gregs[REG_EIP];
	pr_debug("signal_sigsegv: Accessing %p triggered a sigsev, eip is %p\n", info->si_addr, eip);
	mz = find_memzone(info->si_addr);

	if (mz) {

		len = insn_len(eip);
		if (len < 0) {
			fprintf(stderr, "Unknown opcode 0x%02x at %p\n", ((uint8_t*)eip)[0], eip);
			assert(0);
		}
		next_insn = eip + len;

		exepage_unprotect(next_insn);
		tamis_priv.old_opcode = ((uint8_t *)next_insn)[0];
		pr_debug("signal_sigsegv: Setting BREAK at %p, opcode was 0x%02x\n", next_insn, ((uint8_t *)next_insn)[0]);
		((uint8_t *)next_insn)[0] = 0xc3; //BREAK_INSN;
		exepage_protect(next_insn);

		ebp = (void**)ucontext->uc_mcontext.gregs[REG_EBP];
		tamis_priv.to_protect_mem = mz->mem;
		tamis_priv.to_protect_len = mz->len;
		unprotect(mz);

		/* Is the accessed memory being observed ? ... */
		if (mz_includes(info->si_addr, mz)) {
			int ret, protected = 0;

			/* ... yes, take the appropriate mz->action */
			switch(mz->type) {
			case MUTEX_LOCK_PROTECTED:
				ret = pthread_mutex_trylock(mz->action.m);
				if (ret == EBUSY) {
					protected = 1;
				} else {
					pthread_mutex_unlock(mz->action.m);
				}
				fprintf(stderr, "Access @ %p was %sprotected by lock %p\n", eip,
					protected ? "" : "not ", mz->action.m);
				break;
			case CALLBACK:
				mz->action.cb(mz->mem);
				break;
			default:
				assert(0);
			}
		}
	} else {
		fprintf(stderr, "not our sigsegv at %p\n", info->si_addr);
		assert(0);
	}
	asm volatile ("call *%0" : : "m"(eip));

	/* restore the old code */
	pr_debug("signal_segv   : Caught a trap at eip %p\n", eip);
	exepage_unprotect((void *)next_insn);
	pr_debug("signal_segv   : Restoring old opcode: 0x%2x at %p\n", tamis_priv.old_opcode, eip);
	((uint8_t *)next_insn)[0] = tamis_priv.old_opcode;
	exepage_protect((void *)next_insn);

	/* reprotect the zone that triggered the sigsegv/sigtrap stuff */
	protect(tamis_priv.to_protect_mem, tamis_priv.to_protect_len);

	/* locked in signal_segv */
	ret = pthread_mutex_unlock(&tamis_lock);
	assert(ret == 0);

	return;
}

static void signal_trap(int signum, siginfo_t * info, void* stack)
{
	int8_t *eip;
	ucontext_t *ucontext = stack;

	assert(0);
	eip = (int8_t *)ucontext->uc_mcontext.gregs[REG_EIP] - 1;


	ucontext->uc_mcontext.gregs[REG_EIP] = (int)eip;

	return;
}

void tamis_unprotect(void *p)
{
	struct tamis_memzone *mz;
	mz = find_memzone(p);
	if (!mz)
		return;
	unprotect(mz);
	del_memzone(mz);
}

int tamis_protect(void *p, size_t len, enum tamis_type t, void *arg)
{
	struct tamis_memzone *mz;
	mz = add_memzone(p, len);
	mz->type = t;
	mz->action.action = arg;
	return protect(p, len);
}

void *tamis_alloc(size_t size)
{
	return malloc((size / PAGE_SIZE) * PAGE_SIZE + PAGE_SIZE);
}
void tamis_free(void *p)
{
	free(p);
}
int tamis_init()
{
	struct sigaction action;
	void *__attribute__((unused)) lib_handle = NULL;

 	tamis_lock.__data.__kind = PTHREAD_MUTEX_ERRORCHECK_NP;
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


