#ifndef WORAM_H
#define WORAM_H

#include "vm.h"

#define UTM_ARRAY_STARTING_OFFSET 1048*1048 //1MB

uintptr_t woram_array;
uintptr_t woram_array_size;



void initialize_woram_array(void);

#endif