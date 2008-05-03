/*
    tamis_test.c - tamis testing code
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

#define LOOPS 1000000
#define THREADS 200

static int *shared_var;
pthread_mutex_t shared_var_mutex = PTHREAD_MUTEX_INITIALIZER;

void *access_shared_var(void *arg)
{
	int i;
	for (i = 0; i < LOOPS; i++) {
		*shared_var = i;
	}
	return NULL;
}

int f()
{
	return 0;
}

/* Test 3: threaded access */
int main()
{
	int i;
	pthread_t t[THREADS];

	shared_var = tamis_alloc(sizeof(*shared_var));

	tamis_init();
	tamis_protect((void *)shared_var, sizeof(*shared_var), CALLBACK, f);

	for (i = 0; i < THREADS; i++) {
		pthread_create(&t[i], NULL, access_shared_var, NULL);
	}

	for (i = 0; i < THREADS; i++) {
		pthread_join(t[i], NULL);
	}

	tamis_unprotect((void *)shared_var);
	tamis_free(shared_var);

	return 0;
}
