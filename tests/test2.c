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
#include <errno.h>

#include "tamis.h"


static int *shared_var = 0;
pthread_mutex_t shared_var_mutex = PTHREAD_MUTEX_INITIALIZER;

int verify_callback()
{
	if (pthread_mutex_trylock(&shared_var_mutex) == EBUSY) {
		fprintf(stderr, "Access was protected by lock %p\n", &shared_var_mutex);
	} else {
		pthread_mutex_unlock(&shared_var_mutex);
	}
	return 1;
}

/* Test 2: protected single access */
int main()
{
	tamis_init();

	fprintf(stderr, "Lock is %p\n", &shared_var_mutex);

	shared_var = tamis_alloc(sizeof(*shared_var));
	tamis_protect((void *)shared_var, sizeof(*shared_var), CALLBACK, verify_callback);

	pthread_mutex_lock(&shared_var_mutex);
	*shared_var = 1;
	pthread_mutex_unlock(&shared_var_mutex);

	tamis_unprotect((void *)shared_var);
	tamis_free((void *)shared_var);
	return 0;
}
