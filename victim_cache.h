#ifndef VICTIM_CACHE_H
#define VICTIM_CACHE_H

#include "vm.h"
#define CACHE_SIZE 5*RISCV_PAGE_SIZE //2*1024*1024
#define MAX_VICTIM_CACHE_PAGES 5

typedef struct QNode { 
    struct QNode *prev, *next; 
    unsigned pageNumber; // the page number stored in this QNode 
} QNode; 
  
// A Queue (A FIFO collection of Queue Nodes) 
typedef struct Queue { 
    unsigned count; // Number of filled frames 
    unsigned numberOfFrames; // total number of frames 
    QNode *front, *rear; 
} Queue;
  
// A hash (Collection of pointers to Queue Nodes) 
typedef struct Hash { 
    int capacity; // how many pages can be there 
    QNode** array; // an array of queue nodes 
} Hash; 
  


struct victim_cache
{
    unsigned long long used_cache_pages; //= 0;
    unsigned long long free_cache_pages; // = VICTIM_CACHE_PAGES;

    

} victim_cache;


// int is_queue_empty(Queue* queue);
int is_victim_cache_empty();
int is_victim_cache_full();

void initialize_victim_cache(void);
int is_cache_hit(uintptr_t addr); //returns true if cache has addr
void store_page_to_cache(uintptr_t addr); //evicted page is placed in victim cache
void remove_page_from_cache(uintptr_t addr); //removes page from cache







#endif