#include <stdint.h>
#include <stddef.h>
#include "sbi.h"

int mem_share(size_t uid, uintptr_t enclave_addr, size_t enclave_size);
int mem_stop(size_t uid);
#ifdef USE_FREEMEM
uintptr_t enclave_map(uintptr_t base_addr, size_t base_size, uintptr_t ptr);
#endif
