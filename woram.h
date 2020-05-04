#ifndef WORAM_H
#define WORAM_H

#include "vm.h"

#define UTM_ARRAY_STARTING_OFFSET 1048*1048 //1MB
#define POSITION_MAP_SIZE 1024
#define WORAM_SIZE 20

struct woram {
    uintptr_t woram_array;
    uintptr_t woram_array_size;
    uintptr_t *position_map;
    unsigned long long holding_area_size; //N
    unsigned long long main_area_size; //M
    unsigned long long write_access_counter;
} woram;

struct key_utilities
{
    uint8_t *key_chacha;
    uint8_t *key_aes;
    uint8_t *iv_aes;
    uint8_t *Key_hmac;
    uint8_t *z_1;
    uint8_t *z_2;
    uint8_t *key;
    uint8_t *key_hmac;
    uint8_t *z1;
    uint8_t *z2;
};
struct key_utilities keys;

void initialize_woram_array(void);
void initialize_position_map(void);
void sanity_check(void);
void woram_write_access(pages);
void woram_read_access(uintptr_t, pages*);
void set_pos(uintptr_t addr, uintptr_t new_addr);
uintptr_t get_pos(uintptr_t addr);

void store_victim_page_to_woram(uintptr_t victim_page_enclave_va, uintptr_t victim_page_runtime_va, int, int);
void get_page_from_woram(uintptr_t addr, uintptr_t new_alloc_page, uintptr_t *status_find_address, int, int);
void calculate_hmac_woram(pages* p, char* hm, uintptr_t hm_len);

void setup_key_utilities(uint8_t *key_chacha_, uint8_t *key_aes_, uint8_t *iv_aes_, uint8_t *Key_hmac_, 
                uint8_t *z_1_, uint8_t *z_2_, uint8_t *key_, uint8_t *key_hmac_, uint8_t *z1_, uint8_t *z2_);

//Debug Functions
void display_position_map();
void testing();

#endif