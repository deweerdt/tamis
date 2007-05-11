#include <stdio.h>
#include <signal.h>

void sig_handler(int signum)
{
        printf("Catched signal %d", signum);
        exit(0);
}

int main()
{
        int *ptr;
        struct sigaction new_action, old_action;

        // set up new handler to specify new action
        new_action.sa_handler = sig_handler;
        sigemptyset (&new_action.sa_mask);
        new_action.sa_flags = 0;
        // attach SIGSEV to sig_handler
        sigaction(11, &new_action, NULL);


        printf("in loop\n");
        sleep(2);

        ptr = (int *)9;
        printf("%d\n", *ptr); // this should raise a SIGSEV
}
