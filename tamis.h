/*
    tamis.h - Header exporting tamis functions
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

#ifndef __TAMIS_H__
#define __TAMIS_H__

#include <asm/page.h>


void *tamis_alloc(size_t);
void tamis_free(void *);

#ifndef __KERNEL__

#include <stdio.h>
#include <linux/netfilter.h>

#define printk printf
#define KERN_ERR

#endif

static void dump_line(char *data, int offset, int limit)
{
	int i;

	printk(KERN_ERR "%03x:", offset);
	for (i = 0; i < limit; i++) {
		printk(" %02x", (unsigned char)data[offset + i]);
	}
	printk("\n");
}
static void __attribute__((unused)) dump_zone(void *buf, int len)
{
	int i;
	char *data = buf;

	printk(KERN_ERR "================================================================================\n");
	for (i=0; i < len; i+=16) {
		int limit;
		limit = 16;
		if (i + limit > len)
			limit = len - i;
		dump_line(data, i, limit);
	}
	printk(KERN_ERR "================================================================================\n");
}


struct tamis_private {
	uint8_t old_opcode;
	void *to_protect_mem;
	size_t to_protect_len;
	int policy;
	int priority;
};

enum tamis_type {
	MUTEX_LOCK_PROTECTED,
	CALLBACK,
};

struct tamis_memzone {
	void *mem;
	void *page;
	int len;
	enum tamis_type type;
	union {
		pthread_mutex_t *m;
		int (*cb)(void *);
		void *action;
	} action;
};

#ifdef __i386__
#define BREAK_INSN 0xcc
#else
#error "Unknown arch, sorry"
#endif

#define __tamis __attribute__ ((aligned (PAGE_SIZE))) __attribute__((section ("tamis")))

/**
 * @brief Remove a memory zone from being protected by tamis
 *
 * @param p The pointer to the memory to unprotect
 **/
void tamis_unprotect(void *p);

/**
 * @brief Protect memory accesses to a give memory zone with tamis
 *
 * @param p The memory zone to protect
 * @param len The length of the memory zone to protect
 *
 * @return 0 in case of success, -1 otherwise. errno is set with the
 * approriate value
 **/
int tamis_protect(void *p, size_t len, enum tamis_type t, void *arg);

/**
 * @brief Initialize the tamis library
 *
 * @return 0 in case of success, -1 otherwise. errno is set with the
 * approriate value
 **/
int tamis_init();

#endif /* __TAMIS_H__ */
