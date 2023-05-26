#include <stdio.h>
#include <stdlib.h>
#include <sys/signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "ticker.h"
#include "watcher.h"

char *parse_watcher_input(int fd);

volatile sig_atomic_t sigio_flag = 0;

// SIGCHLD signal that informs termination of watcher
void sigchld_handler(int signno, siginfo_t *info, void *context) {
    // siginfo_t *info: contains si_code which has info about watcher      EX: info->si_pid
    // context: pointer to ucontext_t structure that provides context about process state at the time of signal
    printf("SIGCHLD signal recieved\n");

    int status;
    pid_t pid;

    // Reap all terminated child processes
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        // Update watcher table
        // Free watcher resources
        // Close file descriptors, free slots in the watcher table, free memory/resources associated with that terminated watcher
    }
}

// SIGIO signal that reads data from watchers
void sigio_handler(int signno) {
    printf("Received SIGIO signal\n");

    sigio_flag = 1; 
}


int ticker(void) {
    // // SigCHLD
    // struct sigaction sig_chld = {0};

    // // Initialize signal handler
    // sig_chld.sa_sigaction = sigchld_handler;
    // sigemptyset(&sig_chld.sa_mask);
    // sig_chld.sa_flags = SA_SIGINFO;
    // sigaction(SIGCHLD, &sig_chld, NULL);              // sigaction() < 0 == ERROR 

    // // SigIO                                         // CAN USE SIG_IO.MASK TO SPECIFY SIGNALS TO BE BLOCKED
    // struct sigaction sig_io = {0};
    // sig_io.sa_handler = sigio_handler;
    // sigemptyset(&sig_io.sa_mask);                    // Sets signal set to be empty so no signals will be blocked during execution of signal handler
    // sig_io.sa_flags = SA_SIGINFO;                             // No special flags set for signal handler     
    // sigaction(SIGIO, &sig_io, NULL);                 // Changes action of when sigio is recieved      

    // // sigemptyset(&sig_io.sa_mask);                        // Empty set of signals
    // // sigaddset(&ig_io.sa_mask, SIGINT);                   // Adds SIGINT signal to the set
    // // sigprocmask(SIG_BLOCK, &ig_io.sa_mask, NULL);        // Blocks signals in signal set(which is none since set is empty)
    // // sigsuspend(&ig_io.sa_mask);                          // Waits until signal is recieved. Pass signals that you want to be ENABLED not masked


    // // Setup standard input
    // fcntl(STDIN_FILENO, F_SETOWN, getpid());    // set ownership to current process
    // fcntl(STDIN_FILENO, F_SETSIG, SIGIO);       // designate SIGIO as the signal to be sent
    // int flags = fcntl(STDIN_FILENO, F_GETFL);
    // fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK | O_ASYNC | flags);      // set asynchronous I/O

    // // Read from standard input
    // sigset_t sigio_mask;
    // sigemptyset(&sigio_mask);

    // while(1) {
    //     // WATCHER_TYPE *type = &watcher_types[CLI_WATCHER_TYPE];              // Start CLI WATCHER
    //     // Start CLI WATHER here?
    //     fprintf(stdout, "ticker> ");
    //     fflush(stdout);

    //     // Read from input before sigsuspend to help with echo
    //     sigsuspend(&sigio_mask);
        

    //     // Read the standard input from watchers?

    // }
    return 0;
}

void createProcess() {
    //Do forking and pipe here
    int parent_to_child_pipe[2];
    int child_to_parent_pipe[2];

    pipe(parent_to_child_pipe);
    pipe(child_to_parent_pipe);

    // WATCHER *watcher;
    // watcher->parent_to_child_read_fd = parent_to_child_pipe[0];
    // watcher->parent_to_child_write_fd = parent_to_child_pipe[1];
    // watcher->child_to_parent_read_fd = child_to_parent_pipe[0];
    // watcher->child_to_parent_write_fd = child_to_parent_pipe[1];

    // pid_t pid = fork();
    // if(pid == 0) {
    //     // Close unused ends of the pipes
    //     close(parent_to_child_pipe[1]);
    //     close(child_to_parent_pipe[0]);

    //     // Redirect stdin to read from parent process
    //     dup2(parent_to_child_pipe[0], STDIN_FILENO);

    //     // Redirect stdout to write to parent process
    //     dup2(child_to_parent_pipe[1], STDOUT_FILENO);

    //      // Close the original file descriptors for the pipes
    //     close(parent_to_child_pipe[0]);
    //     close(child_to_parent_pipe[1]);
    // }
    
    // else {
    //     // Parent process


    // }

}


char *parse_watcher_input(int fd) {
    char *buffer = malloc(256);
    memset(buffer, 0, 256);
    size_t buffer_size = 0;
    ssize_t n;

    while(1) {
        n = read(fd, buffer + buffer_size, 256);
        // What to do if n == -1 bc there is no input but enter is pressed in the terminal?

        if(n == -1) {
            if(errno == EWOULDBLOCK)
                break;
        }

        else if(n == 0) {
            char *result = malloc(buffer_size + 1);
            memcpy(result, buffer, buffer_size);
            result[buffer_size] = '\0';
            free(buffer);        

            return result;
        }

        else {
            buffer_size += n;
            
            if(sizeof(buffer) <= buffer_size) {
                buffer = realloc(buffer, buffer_size + 64);
            }
        }
    }

    // free(buffer);
    return buffer;
}

