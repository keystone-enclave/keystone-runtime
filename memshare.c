#include "memshare.h"

int mem_share(size_t uid){
   int ret;
   ret = SBI_CALL_1(SBI_SM_MEM_SHARE, (uintptr_t) uid);
   return ret;
}

int mem_stop(size_t uid){
   int ret;
   ret = SBI_CALL_1(SBI_SM_MEM_STOP, (uintptr_t) uid);
   return ret; 
}
