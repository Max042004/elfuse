/* GDB write into a read-touched lazy-zero page. The load before the hardware
 * breakpoint installs the shared zero-page alias in this vCPU's TLB; after GDB
 * writes 'Z', the load following the breakpoint must observe the private page.
 */

.text
.global _start
_start:
    mov x0, #0
    mov x1, #4096
    mov x2, #3                  /* PROT_READ | PROT_WRITE */
    mov x3, #0x22               /* MAP_PRIVATE | MAP_ANONYMOUS */
    mov x4, #-1
    mov x5, #0
    mov x8, #222                /* __NR_mmap */
    svc #0
    mov x19, x0
    ldrb w20, [x19]             /* cache the shared zero-page translation */

gdb_lazy_stop:
    nop                         /* hardware breakpoint: 0x400028 */
    ldrb w0, [x19]
    cmp w0, #'Z'
    cset w0, ne                 /* exit 0 only if the GDB write is visible */
    mov x8, #93                 /* __NR_exit */
    svc #0
