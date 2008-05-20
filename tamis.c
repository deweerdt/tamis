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
#include "opcode.h"

#if 0
#define pr_debug(x, a...) do { \
			 	char __buf[4096]; \
				sprintf(__buf, x, ##a); \
				fprintf(stdout, "tid:0x%x\t%s", (int)pthread_self(), __buf); \
			  } while(0);
#else
#define pr_debug(...) do {} while(0)
#endif

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

LIST_HEAD(listhead, tamis_memzone) memzone_head;
static __tamis pthread_mutex_t memzone_lock = PTHREAD_MUTEX_INITIALIZER;

static void del_memzone(struct tamis_memzone *mz)
{
	LIST_REMOVE(mz, list);
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

static void signal_segv (int sig, siginfo_t *sip, void *context)
{
	void *eip;
	struct tamis_memzone *mz;
	ucontext_t *ucp = context;

	eip = (void *)ucp->uc_mcontext.gregs[REG_RIP];

	pthread_mutex_lock(&memzone_lock);
	mz = find_memzone(sip->si_addr);

	if (mz) {
		int len;

		unprotect(mz);
		len = single_step(eip, &ucp->uc_mcontext, sip->si_addr);

		if (len < 0) {
			fprintf(stderr, "Unknown opcode 0x%02x at %p\n", ((uint8_t*)eip)[0], eip);
			assert(0);
		}

		ucp->uc_mcontext.gregs[REG_RIP] += len;

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
				}
				break;
			case CALLBACK:
				mz->action.cb(mz->mem);
				break;
			default:
				assert(0);
			}
		}
		protect(mz->mem, mz->len);
	} else {
		fprintf(stderr, "not our sigsegv mem at:%p, eip at : %p\n", sip->si_addr, eip);
		assert(0);
	}
	pthread_mutex_unlock(&memzone_lock);

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

	memset(&action, 0, sizeof(action));
	action.sa_sigaction = signal_segv;
	action.sa_flags = SA_SIGINFO;
	if(sigaction(SIGSEGV, &action, NULL) < 0) {
		return -1;
	}

	return 0;
}


