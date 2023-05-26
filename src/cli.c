#include <stdlib.h>

#include "ticker.h"
#include "store.h"
#include "cli.h"
#include "debug.h"
#include "watcher.h"
#include <sys/signal.h>
#include <string.h>

WATCHER *WATCHER_TABLE[512]; 
// void allocateArgs(WATCHER *wp, char *args[]);

WATCHER *cli_watcher_start(WATCHER_TYPE *type, char *args[]) {
    // Duplicate CLI TYPE is called
    WATCHER *cli = malloc(sizeof(WATCHER));
    cli->id = -1;
    cli->type = type;
    cli->args = NULL;

    cli->parent_to_child_write_fd = STDIN_FILENO;
    cli->child_to_parent_read_fd = STDOUT_FILENO;

    cli->parent_to_child_read_fd = STDIN_FILENO;
    cli->child_to_parent_write_fd = STDOUT_FILENO;

    cli->buffer = calloc(1, 64);
    cli->buf_capacity = 64;
    cli->buf_size = 0; 

    WATCHER_TABLE[0] = cli;

    for(int i = 1; i < 512; i++) {
        WATCHER_TABLE[i] = NULL;
    }

    return cli;

}

int cli_watcher_stop(WATCHER *wp) {
    kill(wp->id, SIGTERM);
    free(wp->buffer);
    
    for(int i = 0; i < 512; i++) {
        if(wp->id == WATCHER_TABLE[i]->id) {
            WATCHER_TABLE[i] = NULL;
            break;
        }
    }

    free(wp);
    return 0;
}

int cli_watcher_send(WATCHER *wp, void *arg) {
    // Output ticker> or ??? here
    return 0;
}

int cli_watcher_recv(WATCHER *wp, char *txt) {
     // Command lines typed by the user
    char *input = wp->buffer;
    // char *token;
        
    if(strncmp(input, "start ", 6) == 0) {
        // token = strtok(input, " ");
        // token = strtok(NULL, " ");

        // char *type = token;
        // token = strtok(NULL, " ");
        // char *channel = token;

        // // FInd watcher type
        // int i = 0;
        // WATCHER *w;
        // while(watcher_types[i].name != 0) {
        //     if (strcmp(watcher_types[i].name, type) == 0) {
        //         w = watcher_types[i].start(&watcher_types[i], watcher_types->argv);
        //         break;
        //     }
        //     i++;
        // }

        // Start uwsc program
        // exevcp(w->args[0], w->args);

        // Send JSON TO uwsc

    }

    else if(strncmp(input, "watchers", 8) == 0) {
        // for(int i = 0; i < 512; i++) {

        // }
    }

    else if(strncmp(input, "trace ", 6) == 0) {
        // trace 1 (watcher index in table)
    }

    else if(strncmp(input, "untrace ", 8) == 0) {
        // untrace 1
    }

    else if(strncmp(input, "stop ", 5) == 0) {
        // stop 1
        printf("STOP\n");
    }

    else if(strncmp(input, "show ", 5) == 0) {
        // show bitstamp.net:live_trades_btcusd:price
        printf("SHOW\n");
    }

    else {
        printf("??? Error");
    }

    return 0;
}

int cli_watcher_trace(WATCHER *wp, int enable) {
    // TO BE IMPLEMENTED
    abort();
}

// void allocateArgs(WATCHER *wp, char *args[]) {
//     // Find args size
//     int count = 0;
//     while(args[count] != NULL) {
//         count++;
//     }

//     wp->args = malloc(count * sizeof(char *));
//     for(int i = 0; i < count; i++) {
//         char *copy = malloc((strlen(args[i]) + 1) * sizeof(char));
//         strcpy(copy, args[i]);

//         wp->args[i] = copy; 
//     }

//     wp->args[count] = NULL;
// }
