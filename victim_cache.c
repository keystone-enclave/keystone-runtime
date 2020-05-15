#include "victim_cache.h"

void initialize_victim_cache()
{
    printf("[cache] Entered initialization\n");
    victim_cache.used_cache_pages = 0;
    victim_cache.free_cache_pages = MAX_VICTIM_CACHE_PAGES;

}

