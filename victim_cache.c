#include "victim_cache.h"
#include "malloc.h"

void initialize_victim_cache()
{
    printf("[cache] Entered initialization\n");
    victim_cache.used_cache_pages = 0;
    victim_cache.free_cache_pages = MAX_VICTIM_CACHE_PAGES;
    initialize_hashmap();
    initialize_queue();
    testing_cache();
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
    unsigned int index = addr >> RISCV_PAGE_BITS;
    victim_cache.hashmap[index] = position;
}

QNode* get_node_position(uintptr_t addr)
{
    unsigned int index = addr >> RISCV_PAGE_BITS;
    return victim_cache.hashmap[index];
}

QNode* create_new_node(uintptr_t addr)
{
    QNode *new_node = (QNode*) malloc(sizeof(QNode));
    new_node->next = new_node->prev = 0;
    new_node->pageNumber = addr;
    return new_node;
}

void add_to_queue(uintptr_t addr, Queue *q)
{
    QNode *new_node = create_new_node(addr >> RISCV_PAGE_BITS);
    // printf("[testing] adding addr 0x%zx 0x%zx\n", new_node->pageNumber);
    if(is_queue_empty(q))
        q->front = q->rear = new_node;
    else 
    {
        q->rear->next = new_node;
        new_node->prev = q->rear;
        q->rear = new_node;
    }
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

void move_page_to_cache_from_enclave(uintptr_t addr)
{

}

void move_page_to_enclave_from_cache(uintptr_t addr)
{
    
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

void testing_cache()
{
    printf("[cache] Entered Testing\n");
    Queue *q = victim_cache.lru_queue;
    add_to_queue(0x1000, q);
    add_to_queue(0x2000, q);
    uintptr_t addr = remove_lru_from_queue(q);
    printf("[testing] removed 0x%zx\n", addr);
    display_queue(q);
    add_to_queue(0x3000, q);
    add_to_queue(0x4000, q);
    add_to_queue(0x5000, q);
    display_queue(q);
    addr = remove_mru_from_queue(q);
    printf("[testing] removed mru 0x%zx\n", addr);
    display_queue(q);
    addr = remove_lru_from_queue(q);
    printf("[testing] removed lru 0x%zx\n", addr);
    display_queue(q);
    addr = remove_lru_from_queue(q);
    printf("[testing] removed lru 0x%zx\n", addr);
    display_queue(q);
    addr = remove_mru_from_queue(q);
    printf("[testing] removed mru 0x%zx\n", addr);
    display_queue(q);


}





