OUTPUT_ARCH( "riscv" )

SECTIONS
{
  . = 0xfffffffff0000000;
  PROVIDE(rt_base = .);
  .text : {
    *(.text._start)
    *(.text.encl_trap_handler)
    *(.text)
  }
  . = ALIGN(0x1000);
  .rodata :
  {
    *(.rdata)
    *(.rodata)
  }
  .data : { *(.data) }
  .bss : { *(.bss) }
  . = ALIGN(0x1000);
  .kernel_stack : {
    __kernel_stack_start = .;
    . += 0xfff00;
    PROVIDE(kernel_stack_end = .);
  }
  .malloc_zone :
  {
    __malloc_start_rt = .;
    . = . +  8192;
    __malloc_zone_stop = .;
  }
  _end = .;
}
