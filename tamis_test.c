#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "tamis.h"

#define LOOPS 50

static __tamis int my_shared_var;

void *f_protected(void *arg)
{
	int i;
	pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
	for (i=0; i < LOOPS; i++) {
		pthread_mutex_lock(&m);
		my_shared_var = i;
		memcpy(&my_shared_var, &i, sizeof(i));;
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

	tamis_protect(&my_shared_var, sizeof(my_shared_var));
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
	int i, loops=100000;
	struct timeval tv1, tv2;
	char *disp_prot = "";
	int protect = 1;

#define SIZE (sizeof(int)*126)
	ptr = malloc(SIZE);
	ptr2 = malloc(SIZE);
	ptr3 = malloc(4096);

	if (!ptr || !ptr2 || !ptr3) {
		perror("malloc");
		exit(0);
	}

	/* Runs assignations to ptr[i] with and without protection */
redo_test:
	if (protect) {
		tamis_protect(ptr, SIZE);
	}

	gettimeofday(&tv1, NULL);
	for (i=0; i < loops; i++) {
		ptr[i%(SIZE/sizeof(ptr[0]))] = 2;
	}
	gettimeofday(&tv2, NULL);
	printf("with%s protection:: %lds %ldus\n", disp_prot, tv2.tv_sec - tv1.tv_sec, tv2.tv_usec - tv1.tv_usec);

	if (protect)
		tamis_unprotect(ptr);

	if (protect) {
	       protect = 0;
	       disp_prot = "out";
	       goto redo_test;
	}

	free(ptr);
	free(ptr2);
	free(ptr3);
	puts("OK");

	return NULL;
}

int main()
{
	tamis_init();

	thread_test();
	timing(NULL);
	return 0;
}
