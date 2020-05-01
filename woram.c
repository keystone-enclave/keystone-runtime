#include "woram.h"

void initialize_woram_array()
{
    uintptr_t utm_start = shared_buffer;
    // uintptr_t utm_size = shared_buffer_size;

    woram_array = utm_start + UTM_ARRAY_STARTING_OFFSET;

    //sanity check - access 1st 1MB of the oram array
    char *ptr = (char*) woram_array;
    for( int i=0; i<1024*1024; i++)
        ptr[i] = i;
}


