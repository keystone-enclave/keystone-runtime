#include "victim_cache.h"
#include "malloc.h"

void initialize_victim_cache()
{
    printf("[cache] Entered initialization of victim cache\n");
    victim_cache.used_cache_pages = 0;
    victim_cache.free_cache_pages = MAX_VICTIM_CACHE_PAGES;
    initialize_hashmap();
    initialize_queue();
    // testing_cache();
}

void initialize_queue()
{
    victim_cache.lru_queue = (Queue*) malloc(sizeof(Queue));
    victim_cache.lru_queue->front = 0;
    victim_cache.lru_queue->rear = 0;
}

void initialize_hashmap()
{
    victim_cache.hashmap = (QNode**) malloc(sizeof(QNode*) * MAX_VIRTUAL_PAGES);
    unsigned long i = 0;
    for(i=0; i<MAX_VIRTUAL_PAGES; i++)
        victim_cache.hashmap[i] = 0;
}

int is_queue_empty(Queue *q)
{
    if(q->front == 0)
        return 1;
    return 0;
}

void update_hashmap(uintptr_t addr, QNode *position)
{
    printf("[vcache] Updating hashmap of 0x%zx to 0x%zx\n", addr, position);
    unsigned int index = addr >> RISCV_PAGE_BITS;
    victim_cache.hashmap[index] = position;

}

QNode* get_node_position(uintptr_t addr)
{
    unsigned int index = addr >> RISCV_PAGE_BITS;
    printf("[vcache] Getting node pos of 0x%zx at index 0x%zx\n", addr, index);
    return victim_cache.hashmap[index];
}

QNode* create_new_node(uintptr_t addr)
{
    QNode *new_node = (QNode*) malloc(sizeof(QNode));
    new_node->next = new_node->prev = 0;
    new_node->pageNumber = addr >> RISCV_PAGE_BITS;
    return new_node;
}

QNode* add_to_queue(uintptr_t addr, Queue *q)
{
    QNode *new_node = create_new_node(addr);
    printf("[testing] adding addr to queue 0x%zx 0x%zx\n", addr, new_node->pageNumber);
    if(is_queue_empty(q))
        q->front = q->rear = new_node;
    else 
    {
        q->rear->next = new_node;
        new_node->prev = q->rear;
        q->rear = new_node;
    }
    return new_node;
}

uintptr_t remove_lru_from_queue(Queue *q) //remove from front of the Queue
{
    if(is_queue_empty(q))
    {
        printf("[ERROR] Queue empty. can't remove lru\n");
        return 0;
    }
    uintptr_t addr = q->front->pageNumber << RISCV_PAGE_BITS;
    QNode *node_to_remove = q->front;
    if(q->front == q->rear)
        q->front = q->rear = 0;
    else
    {
        q->front = q->front->next;
        q->front->prev = 0;
    }
    free(node_to_remove);
    return addr;  
}

uintptr_t remove_mru_from_queue(Queue *q) //remove from rear of the Queue
{
    if(is_queue_empty(q))
    {
        printf("[ERROR] Queue empty. can't remove lru\n");
        return 0;
    }
    uintptr_t addr = q->rear->pageNumber << RISCV_PAGE_BITS;
    QNode *node_to_remove = q->rear;
    if(q->front == q->rear)
        q->front = q->rear = 0;
    else
    {
        q->rear = q->rear->prev;
        q->rear->next = 0;
    }
    free(node_to_remove);
    return addr;  
} 

void remove_node_from_queue(QNode *node_to_remove, Queue *q)
{
    if(!node_to_remove)
        return;
    QNode *before = node_to_remove->prev;
    QNode *after = node_to_remove->next;
    if(!before)
        remove_lru_from_queue(q);
    else if(!after)
        remove_mru_from_queue(q);
    else 
    {
        before->next = after;
        after->prev = before;
        free(node_to_remove);
    }
}

int is_victim_cache_full()
{
    if(victim_cache.free_cache_pages == 0)
        return 1;
    return 0;
}

int is_victim_cache_empty()
{
    if(victim_cache.lru_queue->front == 0)
        return 1;
    return 0;
}

int is_in_victim_cache(uintptr_t addr)
{
    QNode* ptr = get_node_position(addr);
    return (ptr != 0);
}

void move_page_to_cache_from_enclave(uintptr_t addr)
{
    //assume cache is not full
    printf("[vcache] Moving 0x%zx to cache\n", addr);
    if(is_victim_cache_full())
    {
        printf("[ERROR] cache full. cant add page from enclave\n");
        return;
    }
    Queue *q = victim_cache.lru_queue;
    QNode *node_ptr = add_to_queue(addr, q);
    update_hashmap(addr, node_ptr);
    display_hashmap();
    display_queue(q);
    victim_cache.free_cache_pages--;
    victim_cache.used_cache_pages++;
}

void move_page_to_enclave_from_cache(uintptr_t addr)
{
    printf("[vcache] Move page 0x%zx to enclave\n", addr);
    QNode *node_ptr = get_node_position(addr);
    update_hashmap(addr, 0);
    display_hashmap();
    remove_node_from_queue(node_ptr, victim_cache.lru_queue);
    display_queue(victim_cache.lru_queue);
    victim_cache.free_cache_pages++;
    victim_cache.used_cache_pages--;
}

uintptr_t get_lru_victim_from_cache()
{
    if(is_victim_cache_empty())
    {
        printf("ERROR - CACHE FULL. CANT GET LRU\n");
        return 0;
    }
    return victim_cache.lru_queue->front->pageNumber << RISCV_PAGE_BITS; // >> or << ??
}

void remove_lru_page_from_cache()
{
    uintptr_t addr = remove_lru_from_queue(victim_cache.lru_queue);
    update_hashmap(addr, 0);
    display_hashmap();
    display_queue(victim_cache.lru_queue);
    victim_cache.free_cache_pages++;
    victim_cache.used_cache_pages--;
}

void display_queue(Queue *q)
{
    QNode *node = q->front;
    while(node)
    {
        printf(" [%zd] ", node->pageNumber);
        node = node->next;
    }
    printf("\n");
}

void display_hashmap()
{
    int size = 15;
    unsigned long i = 0;
    for(i=0; i<size; i++)
        printf("%d -> 0x%zx\n", i, victim_cache.hashmap[i]);
}

void testing_cache()
{
    printf("[cache] Entered Testing\n");
    Queue *q = victim_cache.lru_queue;
    move_page_to_cache_from_enclave(0x1000);
    move_page_to_cache_from_enclave(0x2000);
    move_page_to_cache_from_enclave(0x3000);
    move_page_to_cache_from_enclave(0x4000);
    move_page_to_cache_from_enclave(0x5000);
    move_page_to_cache_from_enclave(0x6000);
    display_queue(q);
    remove_lru_page_from_cache();
    printf("[testing] removed lru \n");
    display_queue(q);
    move_page_to_enclave_from_cache(0x3000);
    printf("[testing] moved page 0x3000 \n");
    display_queue(q);
    move_page_to_enclave_from_cache(0x2000);
    printf("[testing] moved page 0x2000 \n");
    display_queue(q);
    move_page_to_enclave_from_cache(0x5000);
    printf("[testing] moved page 0x5000 \n");
    display_queue(q);

    // addr = remove_mru_from_queue(q);
    // printf("[testing] removed mru 0x%zx\n", addr);
    // display_queue(q);
    // uintptr_t node_addr = get_node_position(0x3000);
    // remove_node_from_queue(node_addr,q);
    // printf("[testing] removed 0x3000 from addr 0x%zx\n", node_addr);
    // display_queue(q);
}





