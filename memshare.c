#include "memshare.h"
#include "mm.h"
#include "freemem.h"
#include "rt_util.h"
#include "common.h"
#include "vm.h"
#include "uaccess.h"

int mem_share(size_t uid, uintptr_t enclave_addr, uintptr_t enclave_size){
   int ret;
   uintptr_t phys_e_addr;
   uintptr_t phys_e_size; 

   uintptr_t addr_phys_e_addr = kernel_va_to_pa(&phys_e_addr);
   uintptr_t addr_phys_e_size = kernel_va_to_pa(&phys_e_size); 

   ret = SBI_CALL_3(SBI_SM_MEM_SHARE, (uintptr_t) uid, addr_phys_e_addr, addr_phys_e_size);

   copy_to_user((void *) enclave_addr, &phys_e_addr, sizeof(uintptr_t));
   copy_to_user((void *) enclave_size, &phys_e_size, sizeof(uintptr_t));
   return ret;
}

int mem_stop(size_t uid){
   int ret;
   ret = SBI_CALL_1(SBI_SM_MEM_STOP, (uintptr_t) uid);
   return ret; 
}

uintptr_t enclave_map(uintptr_t base_addr, size_t base_size, uintptr_t ptr){

  int pte_flags = PTE_W | PTE_D | PTE_R | PTE_U | PTE_A;

  // Set flags
/*  if(prot & PROT_READ)
    pte_flags |= PTE_R;
  if(prot & PROT_WRITE)
    pte_flags |= PTE_W | PTE_D;
  if(prot & PROT_EXEC)
    pte_flags |= PTE_X;
*/
  // Find a continuous VA space that will fit the req. size
  int req_pages = vpn(PAGE_UP(base_size));

 
  if(test_va_range(vpn(ptr), req_pages) != req_pages){
	return 0; 
   }
 
 if(map_pages(vpn(ptr), ppn(base_addr), req_pages, pte_flags) != req_pages){
       return 0;  
   }

  return ptr; 
}
