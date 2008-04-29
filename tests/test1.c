/*
    test1.c - tamis testing code
    Copyright (C) 2008  Frederik Deweerdt <frederik.deweerdt@gmail.com>

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

#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "tamis.h"


static volatile int __tamis shared_var;

pthread_mutex_t shared_var_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Test 1: unprotected single access */
int main()
{
	fprintf(stderr, "Lock is %p\n", &shared_var_mutex);
	tamis_init();
	tamis_protect((void *)&shared_var, sizeof(shared_var), MUTEX_LOCK_PROTECTED, &shared_var_mutex);

	shared_var = 0;

	tamis_unprotect((void *)&shared_var);
	return 0;
}
