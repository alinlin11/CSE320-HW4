#include <stdio.h>
#include <unistd.h>

#include "ticker.h"

typedef struct watcher{
   WATCHER_TYPE *type;
   pid_t id;
   int parent_to_child_read_fd;      
   int parent_to_child_write_fd;   
   int child_to_parent_read_fd;    
   int child_to_parent_write_fd;      
   char **args;              // Can be multiple channels but watcher only keeps track of the first channel.
   char *buffer;
   size_t buf_capacity;
   size_t buf_size;

} WATCHER;

extern WATCHER *WATCHER_TABLE[512];                        // Watcher table
