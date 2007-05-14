#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>

#include "tamis.h"

#define LOOPS 50
static __tamis int my_shared_var;
static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;

void *f_protected(void *arg)
{
	int i;
	for (i=0; i < LOOPS; i++) {
		pthread_mutex_lock(&m);
		my_shared_var = i;
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
	int i, loops=10000;
	struct timeval tv1, tv2;

#define SIZE (sizeof(int)*126)
	ptr = malloc(SIZE);
	ptr3 = malloc(4096);
	ptr2 = malloc(SIZE);

	tamis_protect(ptr, SIZE);

	gettimeofday(&tv1, NULL);
	for (i=0; i < loops; i++) {
		ptr[i%(SIZE/sizeof(ptr[0]))] = 2;
	}
	gettimeofday(&tv2, NULL);
	printf("with protection:: %lds %ldus\n", tv2.tv_sec - tv1.tv_sec, tv2.tv_usec - tv1.tv_usec);

	tamis_unprotect(ptr);

	gettimeofday(&tv1, NULL);
	for (i=0; i < loops; i++) {
		ptr2[i%(SIZE/sizeof(ptr[0]))] = 2;
	}
	gettimeofday(&tv2, NULL);
	printf("without protection: %lds %ldus\n", tv2.tv_sec - tv1.tv_sec, tv2.tv_usec - tv1.tv_usec);

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
	//timing(NULL);
	return 0;
}
