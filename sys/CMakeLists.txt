
set(SYS_SOURCES entry.S boot.c env.c interrupt.c)
add_executable(eyrie-rt ${SYS_SOURCES})

# The ordering of these libraries is important, make sure that any symbols which may be
# required by one library are defined by the time that it is added to this list

target_link_libraries(eyrie-rt
        rt_call rt_mm rt_crypto rt_tmplib rt_util
        gcc $ENV{KEYSTONE_SDK_DIR}/lib/libkeystone-edge.a)
target_link_options(eyrie-rt PRIVATE -static -nostdlib -T $<TARGET_OBJECTS:rt_linkscript>)
add_dependencies(eyrie-rt rt_linkscript)

# Todo: do we need the options log still?