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
#include <sys/queue.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <ucontext.h>
#include <unistd.h>

#include "tamis.h"

#if 0
#define pr_debug(x, a...) do { \
			 	char __buf[4096]; \
				sprintf(__buf, x, ##a); \
				fprintf(stdout, "tid:0x%x\t%s", (int)pthread_self(), __buf); \
			  } while(0);
#else
#define pr_debug(...) do {} while(0)
#endif

static __thread struct tamis_private tamis_priv;
/* Serializes the accesses to the SIGSEGV/SIGTRAP code */
static __tamis pthread_mutex_t tamis_lock = PTHREAD_MUTEX_INITIALIZER;


/* returns the length of the opcode, opcode[0] included */
static int insn_len(uint8_t *opcode)
{
	switch (opcode[0]) {
	case 0xa1:
		return 5;
	case 0xa3:
		return 5;
	case 0xc7: /* takes an arg */
		switch (opcode[1]) {
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
		switch (opcode[1]) {
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
LIST_HEAD(listhead, tamis_memzone) memzone_head;
static __tamis pthread_mutex_t memzone_lock = PTHREAD_MUTEX_INITIALIZER;

static void del_memzone(struct tamis_memzone *mz)
{
	free(mz);
}
static struct tamis_memzone *add_memzone(void *p, size_t len)
{
	struct tamis_memzone *mz = calloc(1, sizeof(*mz));
	if (!mz)
		return NULL;

	mz->mem = p;
	mz->page = p - ((unsigned long)p % PAGE_SIZE);
	mz->len = len;

	LIST_INSERT_HEAD(&memzone_head, mz, list);

	return mz;
}
static inline int mz_includes(void *p, struct tamis_memzone *mz)
{
	return p >= mz->mem && p < (mz->mem + mz->len);
}

static struct tamis_memzone *find_memzone(void *p)
{
	struct tamis_memzone *mz;

	for (mz = memzone_head.lh_first;
	     mz != NULL; mz = mz->list.le_next) {
		if (mz_includes(p, mz))
			return mz;
	}
	pr_debug("find return null for %p\n", p);
	return NULL;
}

static void priority_boost(void)
{
	struct sched_param p;
	struct sched_param p_boosted = { .sched_priority = 99 };
	tamis_priv.policy = sched_getscheduler(0);
	sched_getparam(0, &p);
	tamis_priv.priority = p.sched_priority;

	sched_setscheduler(0, SCHED_FIFO, &p_boosted);
}

static void priority_unboost(void)
{
	struct sched_param p = { .sched_priority = tamis_priv.priority };

	sched_setscheduler(0, tamis_priv.policy, &p);
}

static int nesting = 0;

static void signal_segv (int sig, siginfo_t *sip, void *context)
{
	void *eip;
	greg_t cr2;
	void *next_insn;
	struct tamis_memzone *mz;
	int len, ret;
	ucontext_t *ucp = context;

	/* unlocked after signal_trap */
	ret = pthread_mutex_lock(&tamis_lock);

	assert(ret == 0);
	assert(nesting == 0);
	nesting++;

	priority_boost();

#if defined(__i386__)
	eip = (void *)ucp->uc_mcontext.gregs[REG_EIP];
#else
	eip = (void *)ucp->uc_mcontext.gregs[REG_RIP];
	cr2 = ucp->uc_mcontext.gregs[REG_CR2];
#endif
	printf("signal_sigsegv: Accessing %p triggered a sigsev, eip is %p 0x%X\n", sip->si_addr, eip, cr2);
	pthread_mutex_lock(&memzone_lock);
	mz = find_memzone(sip->si_addr);

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
		((uint8_t *)next_insn)[0] = BREAK_INSN;
		exepage_protect(next_insn);

		tamis_priv.to_protect_mem = mz->mem;
		tamis_priv.to_protect_len = mz->len;
		unprotect(mz);

		/* Is the accessed memory being observed ? ... */
		if (mz_includes(sip->si_addr, mz)) {
			int ret;

			/* ... yes, take the appropriate mz->action */
			switch(mz->type) {
			case MUTEX_LOCK_PROTECTED:
				ret = pthread_mutex_trylock(mz->action.m);
				if (ret != EBUSY) {
					pthread_mutex_unlock(mz->action.m);
					fprintf(stderr, "Access @ %p was not protected by lock %p\n", eip, mz->action.m);
					abort();
				}
				break;
			case CALLBACK:
				mz->action.cb(mz->mem);
				break;
			default:
				assert(0);
			}
		}
	} else {
		fprintf(stderr, "not our sigsegv mem at:%p, eip at : %p\n", sip->si_addr, eip);
		assert(0);
	}
	pthread_mutex_unlock(&memzone_lock);

	return;
}

static void signal_trap(int signum, siginfo_t * info, void* stack)
{
	int ret;
	int8_t *eip;
	ucontext_t *ucontext = stack;

#if defined(__i386__)
	eip = (int8_t *)ucontext->uc_mcontext.gregs[REG_EIP] - 1;
#else
	eip = (int8_t *)ucontext->uc_mcontext.gregs[REG_RIP] - 1;
	/* on x86_64 the ip is restored after the opcode */
	ucontext->uc_mcontext.gregs[REG_RIP] = (greg_t)eip;
#endif

	pr_debug("signal_trap   : Caught a trap at eip %p\n", eip);
	exepage_unprotect(eip);
	pr_debug("signal_trap   : Restoring old opcode: 0x%2x at %p\n", tamis_priv.old_opcode, eip);
	eip[0] = tamis_priv.old_opcode;
	exepage_protect(eip);

	/* reprotect the zone that triggered the sigsegv/sigtrap stuff */
	protect(tamis_priv.to_protect_mem, tamis_priv.to_protect_len);

	priority_unboost();
	nesting--;
	assert(nesting == 0);

	/* locked in signal_segv */
	ret = pthread_mutex_unlock(&tamis_lock);
	assert(ret == 0);

	return;
}

void tamis_unprotect(void *p)
{
	struct tamis_memzone *mz;
	pthread_mutex_lock(&memzone_lock);
	mz = find_memzone(p);
	if (!mz) {
		assert(0);
		return;
	}
	unprotect(mz);
	del_memzone(mz);
	pthread_mutex_unlock(&memzone_lock);
}

int tamis_protect(void *p, size_t len, enum tamis_type t, void *arg)
{
	struct tamis_memzone *mz;
	pthread_mutex_lock(&memzone_lock);
	mz = add_memzone(p, len);
	pthread_mutex_unlock(&memzone_lock);
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
	cpu_set_t cpuset;
	int ret;

	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);

	if (geteuid()) {
		printf("You must be root to use tamis\n");
		exit(0);
	}
	ret = sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
	assert(ret == 0);

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


