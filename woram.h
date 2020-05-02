#ifndef WORAM_H
#define WORAM_H

#include "vm.h"
#include "string.h"

#define UTM_ARRAY_STARTING_OFFSET 1048*1048 //1MB
#define POSITION_MAP_SIZE 1024

uintptr_t woram_array;
uintptr_t woram_array_size;
uintptr_t position_map;


void initialize_woram_array(void);
void initialize_position_map(void);
void sanity_check(void);
void woram_write_access(pages);
void woram_read_access(uintptr_t, pages*);

#endif