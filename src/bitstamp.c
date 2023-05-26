#include <stdlib.h>
#include <stdio.h>
#include <sys/signal.h>
#include <unistd.h>

#include "ticker.h"
#include "bitstamp.h"
#include "debug.h"
#include "watcher.h"

// WATCHER *WATCHER_TABLE[512]; 

WATCHER *bitstamp_watcher_start(WATCHER_TYPE *type, char *args[]) {
    // Add watcher to table
    for(int i = 1; i < 512; i++) {
        if(WATCHER_TABLE[i] == NULL) {
            WATCHER *watcher = malloc(sizeof(WATCHER));
            // Need to set fd and id outside in ticker
            watcher->type = type;
            watcher->args = args;
            watcher->buffer = calloc(1, 64);
            watcher->buf_capacity = 64;
            watcher->buf_size = 0; 

            WATCHER_TABLE[i] = watcher;

            return watcher;
        }
    }

    return NULL;
}

int bitstamp_watcher_stop(WATCHER *wp) {
    // TO BE IMPLEMENTED
    abort();
}

int bitstamp_watcher_send(WATCHER *wp, void *arg) {
    // TO BE IMPLEMENTED
    abort();
}

int bitstamp_watcher_recv(WATCHER *wp, char *txt) {
    // TO BE IMPLEMENTED
    abort();
}

int bitstamp_watcher_trace(WATCHER *wp, int enable) {
    // TO BE IMPLEMENTED
    abort();
}
