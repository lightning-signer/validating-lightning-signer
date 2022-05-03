/* STM32F412 F:1024K R:256K */
/* STM32F413 F:1536K R:320K */
MEMORY
{
  /* NOTE K = KiBi = 1024 bytes */
  FLASH : ORIGIN = 0x08000000, LENGTH = 1024K 
  RAM : ORIGIN = 0x20000000, LENGTH = 256K
}

/* This is where the call stack will be allocated. */
/* The stack is of the full descending type. */
/* NOTE Do NOT modify `_stack_start` unless you know what you are doing */
_stack_start = ORIGIN(RAM) + LENGTH(RAM);

/*
 STM32F413 - 64K region is aliased to this region flanked by reserved areas,
 to fail fast if stack overflows.  Unfortunately, it also causes probe-run to display
 backtraces incorrectly and is not suitable for the STM32F412.

_stack_start = 0x10010000;
*/
