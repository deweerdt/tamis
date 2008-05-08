/*
    test4.c - tamis testing code
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
#include <errno.h>

#include "tamis.h"


int __tamis shared_var = 0x0;

int verify_callback()
{
	return 1;
}

#define LOOPS (1000)

static void print_time(struct timeval before, struct timeval after)
{
	printf("%ld us\n", (after.tv_sec - before.tv_sec) * 1000000 + (after.tv_usec - before.tv_usec));
}

/* Test 4: speed test */
int main()
{
	int i, old_shared_var;
	struct timeval before, after;

	tamis_init();
	tamis_protect((void *)&shared_var, sizeof(shared_var), CALLBACK, verify_callback);

	gettimeofday(&before, NULL);
	for (i=0; i < LOOPS; i++) {
		shared_var += i;
	}
	gettimeofday(&after, NULL);

	old_shared_var = shared_var;

	print_time(before, after);

	tamis_unprotect((void *)&shared_var);

	shared_var = 0;
	gettimeofday(&before, NULL);
	for (i=0; i < LOOPS; i++) {
		shared_var += i;
	}
	gettimeofday(&after, NULL);

	print_time(before, after);

	printf("%d == %d\n", shared_var, old_shared_var);
	return !(shared_var == old_shared_var);
}
