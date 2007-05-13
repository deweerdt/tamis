#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <limits.h>
#include <execinfo.h>
#include <sys/wait.h>
#include <sys/types.h>


#if defined(__i386__)

#define BUF_SIZE 255
/* protects get_addr2line global variables */
pthread_mutex_t a2l_mutex = PTHREAD_MUTEX_INITIALIZER;

static char * get_addr2line(char *binary, void *ip)
{
	/* Shared by all the calls to get_addr2line
	   they are protected by a2l_mutex */
	static int to_parent[2];
	static int to_child[2];
	static int inited = 0;

	char *args[6];
	char *buf;
	char pointer[21];
	int ret;

	buf = calloc(1, BUF_SIZE);
	if (!buf)
		goto err;


	pthread_mutex_lock(&a2l_mutex);
	if (!inited) {
		if (pipe(to_parent) < 0) {
			goto err1;
		}

		if (pipe(to_child) < 0) {
			goto err1;
		}

		switch (fork()) {
			case 0:
				if (dup2(to_parent[1], STDOUT_FILENO) < 0) {
					_exit(-1);
				}
				if (dup2(to_child[0], STDIN_FILENO) < 0) {
					_exit(-1);
				}
				close(to_parent[0]);
				close(to_child[1]);
				args[0] = "addr2line";
				args[1] = "-e";
				args[2] = binary;
				args[3] = "-f";
				args[4] = NULL;
				execvp("/usr/bin/addr2line", args);
				perror("exec");
				_exit(-1);
				break;
			case -1:
				perror("fork");	
				pthread_mutex_unlock(&a2l_mutex);
				return binary;
		}
		inited = 1;
	}

	sprintf(pointer, "%p\n", ip);
	write(to_child[1], pointer, strlen(pointer));
	while ((ret = read(to_parent[0], buf, BUF_SIZE)) > 0) {
		if (ret < BUF_SIZE || buf[BUF_SIZE-1] == '\0' || buf[BUF_SIZE-1] == '\n') {
			break;
		}
	}
	pthread_mutex_unlock(&a2l_mutex);
	return buf;
err1:
	free(buf);
	pthread_mutex_unlock(&a2l_mutex);
err:
	return binary;
}

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
void pretty_bt_to_str(char *str)
{
	int i, n;
	char *line, *pline;
	char function[512], file[PATH_MAX];
	char exe_path[PATH_MAX];
	void *bt_addresses[255];
	char buf[512];
	int nb_addr;

	n = readlink("/proc/self/exe", exe_path, ARRAY_SIZE(exe_path));
	if (n < 0) {
		sprintf(str, "cannot read /proc/self/exe\n");
		return;
	}

	exe_path[n] = '\0';

	nb_addr = backtrace(bt_addresses, ARRAY_SIZE(bt_addresses));
	for (n=0; n < nb_addr; n++) {
		pline = line = get_addr2line(exe_path, bt_addresses[n]);
		/* something went wrong with addr2line, fall back to 
		 * bare adresses */
		if (exe_path == line) {
			sprintf(buf, "%p\n", bt_addresses[n]);
			strcat(str, buf);
			continue;
		}
		for (i=0; *pline != '\n'; i++) {
			function[i] = *pline++;
		}
		function[i] = '\0';
		pline++;

		for (i=0; *pline != '\n'; i++) {
			file[i] = *pline++;
		}
		file[i] = '\0';

		sprintf(buf, "%s():%s\n", function, file);
		strcat(str, buf);
		free(line);
	}
}

void pretty_bt_to_FILE(FILE *file)
{
	char bt_str[2048];

	memset(bt_str, 0, ARRAY_SIZE(bt_str));
	pretty_bt_to_str(bt_str);
	fprintf(file, "%s", bt_str);
}

void pretty_bt()
{
	pretty_bt_to_FILE(stderr);
}

#define PRETTY_BT_TEST
#ifdef PRETTY_BT_TEST
void f()
{
	char buf[2048];
	memset(buf, 0, ARRAY_SIZE(buf));
	pretty_bt_to_str(buf);
	//pretty_bt();
}
int main()
{
	int i;
	for (i=0; i < 100000; i++) {
		f();
	}
	return 0;
}
#endif /* PRETTY_BT_TEST */

#else

void pretty_bt_to_str(char *str) {}
void pretty_bt_to_FILE(FILE *file) {}
void pretty_bt() {}


#endif /* __i386__ */
