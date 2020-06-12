#ifndef VICTIM_CACHE_H
#define VICTIM_CACHE_H

#include "vm.h"
#define CACHE_SIZE 5*RISCV_PAGE_SIZE //2*1024*1024
#define MAX_VICTIM_CACHE_PAGES 5
#define MAX_VIRTUAL_PAGES 100

typedef struct QNode { 
    uintptr_t pageNumber; // the page number stored in this QNode
    struct QNode *prev, *next; 
     
} QNode; 
  
// A Queue (A FIFO collection of Queue Nodes) 
typedef struct Queue { 
    // unsigned count; // Number of filled frames 
    // unsigned numberOfFrames; // total number of frames 
    QNode *front, *rear; 
} Queue;
  
struct victim_cache
{
    QNode **hashmap;
    Queue *lru_queue;
    unsigned long long used_cache_pages; //= 0;
    unsigned long long free_cache_pages; // = VICTIM_CACHE_PAGES;
} victim_cache;

//internal functions
void initialize_queue();
void initialize_hashmap();
QNode* create_new_node(uintptr_t addr);
int is_queue_empty(Queue *q);
void update_hashmap(uintptr_t addr, QNode *position);
QNode* get_node_position(uintptr_t addr);
QNode* add_to_queue(uintptr_t ele, Queue *q); //add element to rear end of queue
uintptr_t remove_lru_from_queue(Queue *q);
uintptr_t remove_mru_from_queue(Queue *q);
void remove_node_from_queue(QNode *node_to_remove, Queue *q);
void testing_cache();

//cache functions
void move_page_to_cache_from_enclave(uintptr_t addr);
void move_page_to_enclave_from_cache(uintptr_t addr);
uintptr_t get_lru_victim_from_cache();
void remove_lru_page_from_cache();
int is_victim_cache_full();
int is_victim_cache_empty();
void initialize_victim_cache();
int is_in_victim_cache(uintptr_t addr);
void move_lru_to_mru_in_cache();

//debug functions
void display_queue(Queue *q);
void display_hashmap();



#endif