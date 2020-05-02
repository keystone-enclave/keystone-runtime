#include "woram.h"

void initialize_woram_array()
{
    uintptr_t utm_start = shared_buffer;
    // uintptr_t utm_size = shared_buffer_size;

    woram_array = utm_start + UTM_ARRAY_STARTING_OFFSET;
    sanity_check();
    
}

void sanity_check()
{
    //sanity check - access 1st 1MB of the oram array
    char *ptr = (char*) woram_array;
    for( int i=0; i<1024*1024; i++)
        ptr[i] = i;

    //sanity check - access 1st 1000 pages of the oram array
    pages *pages_ptr = (pages*) woram_array;
    // printf("size of 1 page struct is 0x%zx\n", sizeof(pages)); //4152
    for(int i=0; i<1000; i++)
        pages_ptr[i].address = woram_array;

    if (pages_ptr[9].address != woram_array)
    {
        printf("[runtime] woram sanity check failed. Exiting\n");
        sbi_exit_enclave(-1);
    }
}

void initialize_position_map(void)
{
    //TODO - initialize position_map using malloc
}

void woram_write_access(pages victim_page)
{
    printf("[woram] write access\n");
    pages *array_ptr = (pages*) woram_array;
    uintptr_t page_va = victim_page.address;
    // printf("[woram] array va 0x%zx\n", page_va);
    unsigned long page_vpn = page_va >> RISCV_PAGE_BITS;
    // printf("[woram] array index 0x%zx\n", page_vpn);
    array_ptr[page_vpn] = victim_page;
}

void woram_read_access(uintptr_t page_va, pages* returned_page)
{
    printf("[woram] read access\n");
    pages *array_ptr = (pages*) woram_array;
    unsigned long page_vpn = page_va >> RISCV_PAGE_BITS;
    printf("[woram] array index 0x%zx\n", page_vpn);
    pages page_read = array_ptr[page_vpn];
    memcpy(returned_page, &page_read, sizeof(pages));
}


