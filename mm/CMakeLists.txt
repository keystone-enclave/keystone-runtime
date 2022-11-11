
set(MM_SOURCES vm.c)

if(FREEMEM)
    list(APPEND MM_SOURCES mm.c freemem.c)
endif()

if(PAGING)
    list(APPEND MM_SOURCES paging.c)
endif()

if(PAGE_CRYPTO OR PAGE_HASH)
    list(APPEND MM_SOURCES page_swap.c)
endif()

add_library(rt_mm ${MM_SOURCES})