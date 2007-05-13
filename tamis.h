/*
    tamis.h - Header exporting tamis functions
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

#ifndef __TAMIS_H__
#define __TAMIS_H__

struct tamis_tls {
	uint8_t old_opcode;
	void *to_protect_mem;
	size_t to_protect_len;
	int lock_level;
};

struct tamis_memzone {
	void *mem;
	void *page;
	int len;
};
#define BREAK_INSN 0xcc

#define PAGE_SIZE 4096

/**
 * @brief Remove a memory zone from being protected by tamis
 *
 * @param p The pointer to the memory to unprotect 
 **/
void tamis_unshare(void *p);

/**
 * @brief Protect memory accesses to a give memory zone with tamis
 *
 * @param p The memory zone to protect 
 * @param len The length of the memory zone to protect
 *
 * @return 0 in case of success, -1 otherwise. errno is set with the
 * approriate value
 **/
int tamis_share(void *p, size_t len);

/**
 * @brief Initialize the tamis library
 * The following actions are taken:
 * - install SIGSEGV and SIGTRAP signal handlers
 * - re-route pthread_mutex_{un,}lock calls
 *
 * @return 0 in case of success, -1 otherwise. errno is set with the
 * approriate value
 **/
int tamis_init();

#endif /* __TAMIS_H__ */
