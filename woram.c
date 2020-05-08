#include "woram.h"
#include "ssha3.h"
#include "aess.h"
#include "string.h"
#include "malloc.h"

void initialize_woram_array()
{
    uintptr_t utm_start = shared_buffer;
    woram.woram_array = utm_start + UTM_ARRAY_STARTING_OFFSET;

    woram.main_area_size = SCALING_FACTOR * WORAM_SIZE;
    woram.holding_area_size = WORAM_SIZE - woram.main_area_size;
    printf("Main Area N = %zd, Holding ARea M = %zd\n", woram.main_area_size, woram.holding_area_size);
    initialize_position_map();
    woram.write_access_counter = 0;
    sanity_check();
    // display_position_map();
    // testing();
}

void initialize_position_map(void)
{
    woram.position_map = (uintptr_t*) malloc( sizeof(uintptr_t) * woram.main_area_size);
    for(uintptr_t addr = 0; addr < woram.main_area_size; addr ++ )
        woram.position_map[addr] = addr; // va = pa

}

void display_position_map()
{
    printf("[woram] Displaying Position Map Contents of size %zd\n", woram.main_area_size);
    for(uintptr_t addr = 0; addr < woram.main_area_size; addr ++ )
    {
        printf("[woram] Logical Address : 0x%zx , Physical Address : 0x%zx\n", addr, woram.position_map[addr]);
    }
}

void sanity_check()
{
    //sanity check - access 1st 1MB of the oram array
    char *ptr = (char*) woram.woram_array;
    for( int i=0; i<1024*1024; i++)
        ptr[i] = i;

    //sanity check - access 1st 1000 pages of the oram array
    pages *pages_ptr = (pages*) woram.woram_array;
    // printf("size of 1 page struct is 0x%zx\n", sizeof(pages)); //4152
    for(int i=0; i<1000; i++)
        pages_ptr[i].address = woram.woram_array;

    if (pages_ptr[9].address != woram.woram_array)
    {
        printf("[runtime] woram sanity check failed. Exiting\n");
        sbi_exit_enclave(-1);
    }
}

void testing()
{
    uintptr_t N = 20; //woram.main_area_size;
    uintptr_t M = 10; //woram.holding_area_size;
    
    for(int i = 0; i <30; i++)
    {
      unsigned long long start = ((unsigned long long)(i*(N/(double)M)))%N;
      unsigned long long end = ((unsigned long long)((i+1)*(N/(double)M)))%N;
      if (end < start) end = N;
      printf("access = %zd, start = %zd, end = %zd\n", i, start, end);
    }
}

void set_pos(uintptr_t addr, uintptr_t new_addr_index)
{
    uintptr_t addr_index = addr >> RISCV_PAGE_BITS;
    woram.position_map[addr_index] = new_addr_index;
}
uintptr_t get_pos(uintptr_t addr)
{
    return woram.position_map[addr];
}

uintptr_t write_to_holding_area(pages data)
{
    unsigned long long i = woram.write_access_counter;
    uintptr_t N = woram.main_area_size;
    uintptr_t M = woram.holding_area_size;
    uintptr_t holding_area_index = N + i%M; 
    // printf("Writing to holding area index 0x%zx\n", holding_area_index);
    pages *array_ptr = (pages*) woram.woram_array;
    array_ptr[holding_area_index] = data;
    return holding_area_index;
}

void refresh_main_area()
{
    printf("[woram] refresh main area called\n");
    // display_position_map();
    uintptr_t N = woram.main_area_size;
    uintptr_t M = woram.holding_area_size;
    unsigned long long i = woram.write_access_counter;
    pages *array_ptr = (pages*) woram.woram_array;
    unsigned long long start = ((unsigned long long)(i*(N/(double)M)))%N;
    unsigned long long end = ((unsigned long long)((i+1)*(N/(double)M)))%N;
    if (end < start) end = N;
    printf("Write access %zd, refreshing addresses [%zd,%zd)", i, start, end);
    for(uintptr_t addr = start; addr < end; addr++)
    {
      uintptr_t updated_position = get_pos(addr);
      // printf("[refresh] Updated position of 0x%lx is 0x%lx\n", addr, updated_position);
      pages updated_page = array_ptr[updated_position];
      //TODO - add flags to decrypt then encrypt again
      decrypt_page((uint8_t*)updated_page.data,RISCV_PAGE_SIZE,(uint8_t*)keys.key_aes,(uint8_t*)keys.iv_aes);
      decrypt_page((uint8_t*)&updated_page.ver_num,2*sizeof(uintptr_t),(uint8_t*)keys.key_aes,(uint8_t*)keys.iv_aes);
      encrypt_page((uint8_t*)updated_page.data,RISCV_PAGE_SIZE,(uint8_t*)keys.key_aes,(uint8_t*)keys.iv_aes);
      encrypt_page((uint8_t*)&updated_page.ver_num,2*sizeof(uintptr_t),(uint8_t*)keys.key_aes,(uint8_t*)keys.iv_aes);
      array_ptr[addr] = updated_page;
      set_pos(addr << RISCV_PAGE_BITS, addr);
    }
}

void woram_write_access(pages victim_page)
{
    // printf("[woram] write access Counter %zd\n", woram.write_access_counter);
    uintptr_t page_va = victim_page.address;
    //TODO - validate page_va if req
    uintptr_t position = write_to_holding_area(victim_page);
    set_pos(page_va, position); //update position map
    refresh_main_area();
    woram.write_access_counter++;
}

void woram_read_access(uintptr_t page_va, pages* returned_page)
{
    // printf("[woram] read access\n");
    pages *array_ptr = (pages*) woram.woram_array;
    uintptr_t page_vpn = page_va >> RISCV_PAGE_BITS;
    // printf("[woram] array index 0x%zx\n", page_vpn);
    uintptr_t actual_index = get_pos(page_vpn);
    // printf("[woram] actual index 0x%zx\n", actual_index);
    pages page_read = array_ptr[actual_index];
    memcpy(returned_page, &page_read, sizeof(pages));
}

void store_victim_page_to_woram(uintptr_t victim_page_enclave_va, uintptr_t victim_page_runtime_va,
            int confidentiality, int authentication)
{
  pages victim_page;
  victim_page.address = victim_page_enclave_va;
  memcpy((void*)victim_page.data,(void*)victim_page_runtime_va, RISCV_PAGE_SIZE);
  // printf("[woram] victim page addr 0x%lx\n", victim_page.address);
  version_numbers[vpn(victim_page_enclave_va)]++;
  victim_page.ver_num=version_numbers[vpn(victim_page_enclave_va)];
  if(confidentiality)
  {
    encrypt_page((uint8_t*)victim_page.data,RISCV_PAGE_SIZE,(uint8_t*)keys.key_aes,(uint8_t*)keys.iv_aes);
    encrypt_page((uint8_t*)&victim_page.ver_num,2*sizeof(uintptr_t),(uint8_t*)keys.key_aes,(uint8_t*)keys.iv_aes);
  }
  if(authentication)
    calculate_hmac_woram(&victim_page,victim_page.hmac,HASH_SIZE);

  woram_write_access(victim_page);
  // display_position_map();
}

void get_page_from_woram(uintptr_t addr, uintptr_t new_alloc_page, uintptr_t *status_find_address, 
                unsigned long access_mode, int confidentiality, int authentication)
{
  // printf("[runtime] Getting page from woram\n");
  pages *returned_page = (pages*)malloc(sizeof(pages)); 
  woram_read_access(addr, returned_page);
  pages brought_page = *returned_page;
  if(authentication)
  {
    char calc_hmac[HASH_SIZE];
    calculate_hmac_woram(&brought_page,calc_hmac,HASH_SIZE);
    if(!check_hashes((void*)calc_hmac ,HASH_SIZE, (void*)brought_page.hmac ,HASH_SIZE ))
    {
      printf("[runtime] Page corrupted. HMAC integrity check failed.  Fatal error for address 0x%lx\n",brought_page.address);
      sbi_exit_enclave(-1);
    }
  }
  if(confidentiality)
  {
    decrypt_page((uint8_t*)brought_page.data,RISCV_PAGE_SIZE,(uint8_t*)keys.key_aes,(uint8_t*)keys.iv_aes);
    decrypt_page((uint8_t*)&brought_page.ver_num,2*sizeof(uintptr_t),(uint8_t*)keys.key_aes,(uint8_t*)keys.iv_aes);
  }
  // now check version numbers
  if(authentication && version_numbers[vpn(addr)] !=  brought_page.ver_num)
  {
    printf("[runtime] Page corrupted(Possibly a replay attack).  Fatal error for address 0x%lx and brought_page.ver_num= 0x%lx and version_num[]=0x%lx\n",brought_page.address,brought_page.ver_num,version_numbers[vpn(addr)]);
    sbi_exit_enclave(-1);
  }
  
  memcpy((void*)new_alloc_page,(void*)brought_page.data,RISCV_PAGE_SIZE);
  int flags = PTE_A | PTE_V|PTE_R | PTE_X | PTE_W | PTE_U  | PTE_L;
  if (access_mode == 1) //write access
    flags = flags | PTE_D;
  //updating the page table entry with the address of the newly allcated page
  *status_find_address = pte_create( ppn(__pa(new_alloc_page) ), flags); 

  *status_find_address =(*status_find_address)|PTE_V|PTE_E; //remove this later
  asm volatile ("fence.i\t\nsfence.vma\t\n");
  free(returned_page);
  // display_position_map();

}

void calculate_hmac_woram(pages* p, char* hm, uintptr_t hm_len)
{
  char hash_calc[HASH_SIZE];
  sha3_ctx_t sha3;
  sha3_init(&sha3, HASH_SIZE);
  char c[16];
  xor_op((char*)keys.Key_hmac,(char*)keys.z_2,c,AES_KEYLEN);
  sha3_update(&sha3, (void*)c, AES_KEYLEN);
  sha3_update(&sha3, (void*)(*p).data, RISCV_PAGE_SIZE);
  sha3_update(&sha3, (void*)&((*p).ver_num), 2*sizeof(uintptr_t));

  sha3_final((void*)hash_calc, &sha3);
  char c2[16];
  xor_op((char*)keys.Key_hmac,(char*)keys.z_1,c2,AES_KEYLEN);
  sha3_ctx_t sha32;
  sha3_init(&sha32, HASH_SIZE);
  sha3_update(&sha32, (void*)c2, AES_KEYLEN);
  sha3_update(&sha32, (void*)hash_calc, HASH_SIZE);
  sha3_final((void*)hm, &sha32);
}

void setup_key_utilities(uint8_t *key_chacha_, uint8_t *key_aes_, uint8_t *iv_aes_, uint8_t *Key_hmac_, 
                uint8_t *z_1_, uint8_t *z_2_, uint8_t *key_, uint8_t *key_hmac_, uint8_t *z1_, uint8_t *z2_)
{
    keys.key_chacha  = key_chacha_;
    keys.key_aes     = key_aes_;
    keys.iv_aes      = iv_aes_;
    keys.Key_hmac    = Key_hmac_;
    keys.z_1         = z_1_;
    keys.z_2         = z_2_;
    keys.key         = key_;
    keys.key_hmac    = key_hmac_;
    keys.z1          = z1_;
    keys.z2          = z2_;
}




