
set(CALL_SOURCES sbi.c syscall.c)

if(LINUX_SYSCALL_WRAPPING)
    list(APPEND CALL_SOURCES linux_wrap.c)
endif()

if(IO_SYSCALL_WRAPPING)
    list(APPEND CALL_SOURCES io_wrap.c)
endif()

if(NET_SYSCALL_WRAPPING)
    list(APPEND CALL_SOURCES net_wrap.c)
endif()

add_library(rt_call STATIC ${CALL_SOURCES})
