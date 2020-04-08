#define QUEUE_FULL 1
#define QUEUE_EMPTY 2
#define ENQUE_SUCCESS 3
#define DEQUE_SUCCESS 4


uintptr_t place_new_page(uintptr_t item_org_va, uintptr_t item_enc_va);
uintptr_t remove_victim_page();
uintptr_t get_queue_size();
void clear_bits();

void show_queue_contents();
void testing_que();
