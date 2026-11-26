# ============================================================================
# adico_boot.S -- Adico DOS boot entry and low-level CPU helpers (x86_64)
#
#   * Multiboot (v1) header, 32-bit entry, switch to 64-bit long mode
#   * Identity-mapped first 4 GiB using 2 MiB pages
#   * 64-bit GDT, 48 exception/IRQ stubs plus the int 0x80 syscall stub
#   * Port I/O, interrupt-flag, context-switch and memory-string helpers
#
# Assembler syntax: GNU as, Intel syntax (assembled through gcc).
# ============================================================================
        .intel_syntax noprefix

        .set MB_MAGIC, 0x1BADB002
        .set MB_FLAGS, 0x00000003           # bit 0: page-align modules, bit 1: memory info

# ---------------------------------------------------------------------------
# Multiboot header (must live in the first 8 KiB of the image)
# ---------------------------------------------------------------------------
        .section .multiboot, "a"
        .align 4
        .long MB_MAGIC
        .long MB_FLAGS
        .long -(MB_MAGIC + MB_FLAGS)

# ---------------------------------------------------------------------------
# Boot-time memory: page tables and the initial stack. Kept outside the C
# .bss range so the kernel's BSS clearing never touches them.
# ---------------------------------------------------------------------------
        .section .bootbss, "aw", @nobits
        .align 4096
pml4:   .skip 4096
pdpt:   .skip 4096
pd:     .skip 4096 * 4                      # four page directories = 4 GiB
        .align 16
boot_stack_bottom:
        .skip 65536
boot_stack_top:

# ---------------------------------------------------------------------------
# 32-bit entry: GRUB/QEMU enters here in protected mode (EAX=magic, EBX=info)
# ---------------------------------------------------------------------------
        .section .text.boot, "ax"
        .code32
        .global _start
_start:
        cli
        cld
        mov     esp, offset boot_stack_top
        mov     edi, eax                    # keep multiboot magic in EDI
        mov     esi, ebx                    # keep multiboot info pointer in ESI

        # Require CPUID extended leaf 0x80000001 with the long-mode bit.
        mov     eax, 0x80000000
        cpuid
        cmp     eax, 0x80000001
        jb      no_long_mode
        mov     eax, 0x80000001
        cpuid
        test    edx, (1 << 29)
        jz      no_long_mode

        # Zero PML4, PDPT and the four PDs (6 pages).
        push    edi
        mov     edi, offset pml4
        xor     eax, eax
        mov     ecx, (6 * 4096) / 4
        rep stosd
        pop     edi

        # PML4[0] -> PDPT
        mov     eax, offset pdpt
        or      eax, 3
        mov     [pml4], eax

        # PDPT[0..3] -> PD0..PD3
        xor     ecx, ecx
1:      mov     eax, ecx
        shl     eax, 12
        add     eax, offset pd
        or      eax, 3
        mov     [pdpt + ecx * 8], eax
        inc     ecx
        cmp     ecx, 4
        jb      1b

        # PD[i] = i * 2 MiB | present | writable | page-size
        xor     ecx, ecx
2:      mov     eax, ecx
        shl     eax, 21
        or      eax, 0x83
        mov     [pd + ecx * 8], eax
        inc     ecx
        cmp     ecx, 2048
        jb      2b

        # Enable PAE, load CR3, set EFER.LME, enable paging.
        mov     eax, cr4
        or      eax, (1 << 5)
        mov     cr4, eax
        mov     eax, offset pml4
        mov     cr3, eax
        mov     ecx, 0xC0000080
        rdmsr
        or      eax, (1 << 8)
        wrmsr
        mov     eax, cr0
        or      eax, (1 << 31)
        mov     cr0, eax

        # Load the 64-bit GDT and far-return into the 64-bit code segment.
        lgdt    [gdt_ptr]
        push    0x08
        push    offset long_entry
        retf

no_long_mode:
        mov     dword ptr [0xB8000], 0x4F524F45     # "ER"
        mov     dword ptr [0xB8004], 0x4F3A4F52     # "R:"
        mov     dword ptr [0xB8008], 0x4F364F34     # "46"
        mov     dword ptr [0xB800C], 0x4F424F2D     # "-B"
3:      hlt
        jmp     3b

# ---------------------------------------------------------------------------
# 64-bit entry
# ---------------------------------------------------------------------------
        .code64
long_entry:
        mov     ax, 0x10
        mov     ds, ax
        mov     es, ax
        mov     ss, ax
        xor     eax, eax
        mov     fs, ax
        mov     gs, ax
        lea     rsp, [rip + boot_stack_top]

        mov     r12d, edi                   # multiboot magic
        mov     r13d, esi                   # multiboot info pointer
        lea     rdi, [rip + __bss_start]
        lea     rcx, [rip + __bss_end]
        sub     rcx, rdi
        xor     eax, eax
        rep stosb

        mov     edi, r12d
        mov     esi, r13d
        call    kmain
        cli
4:      hlt
        jmp     4b

# ---------------------------------------------------------------------------
# GDT: null, 64-bit code (0x08), data (0x10)
# ---------------------------------------------------------------------------
        .section .data
        .align 8
gdt:
        .quad   0x0000000000000000
        .quad   0x00AF9A000000FFFF
        .quad   0x00CF92000000FFFF
gdt_end:
gdt_ptr:
        .word   gdt_end - gdt - 1
        .quad   gdt

# ---------------------------------------------------------------------------
# Interrupt stubs
# ---------------------------------------------------------------------------
        .section .text
        .code64

.macro ISR_NOERR n
        .global isr_stub_\n
isr_stub_\n:
        push    0
        push    \n
        jmp     isr_common
.endm

.macro ISR_ERR n
        .global isr_stub_\n
isr_stub_\n:
        push    \n
        jmp     isr_common
.endm

        .irp n, 0,1,2,3,4,5,6,7,9,15,16,18,19,20,21,22,23,24,25,26,27,28,29,31
        ISR_NOERR \n
        .endr
        .irp n, 8,10,11,12,13,14,17,30
        ISR_ERR \n
        .endr
        .irp n, 32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47
        ISR_NOERR \n
        .endr
        ISR_NOERR 128

# Common path. Frame layout matches "struct regs" in adico_kernel.c.
isr_common:
        push    rax
        push    rbx
        push    rcx
        push    rdx
        push    rsi
        push    rdi
        push    rbp
        push    r8
        push    r9
        push    r10
        push    r11
        push    r12
        push    r13
        push    r14
        push    r15
        cld
        mov     rdi, rsp
        call    isr_dispatch
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     rbp
        pop     rdi
        pop     rsi
        pop     rdx
        pop     rcx
        pop     rbx
        pop     rax
        add     rsp, 16                     # drop vector and error code
        iretq

        .section .data
        .align 8
        .global isr_stub_table
isr_stub_table:
        .irp n, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47
        .quad   isr_stub_\n
        .endr

# ---------------------------------------------------------------------------
# Low-level helpers (System V AMD64 calling convention)
# ---------------------------------------------------------------------------
        .section .text
        .code64

        .global port_outb                   # void port_outb(u16 port, u8 val)
port_outb:
        mov     edx, edi
        mov     eax, esi
        out     dx, al
        ret

        .global port_inb                    # u8 port_inb(u16 port)
port_inb:
        mov     edx, edi
        xor     eax, eax
        in      al, dx
        ret

        .global port_outw                   # void port_outw(u16 port, u16 val)
port_outw:
        mov     edx, edi
        mov     eax, esi
        out     dx, ax
        ret

        .global port_inw                    # u16 port_inw(u16 port)
port_inw:
        mov     edx, edi
        xor     eax, eax
        in      ax, dx
        ret

        .global irq_save                    # u64 irq_save(void): returns RFLAGS, clears IF
irq_save:
        pushfq
        pop     rax
        cli
        ret

        .global irq_restore                 # void irq_restore(u64 flags)
irq_restore:
        test    rdi, 0x200
        jz      1f
        sti
1:      ret

        .global cpu_sti
cpu_sti:
        sti
        ret

        .global cpu_cli
cpu_cli:
        cli
        ret

        .global cpu_halt
cpu_halt:
        hlt
        ret

        .global cpu_cr2
cpu_cr2:
        mov     rax, cr2
        ret

        .global rdtsc_read
rdtsc_read:
        rdtsc
        shl     rdx, 32
        or      rax, rdx
        ret

        .global idt_load                    # void idt_load(const void *idtr)
idt_load:
        lidt    [rdi]
        ret

# void ctx_switch(u64 *old_sp, u64 new_sp)
# Saves callee-saved registers on the old stack, swaps stacks, restores.
        .global ctx_switch
ctx_switch:
        push    rbp
        push    rbx
        push    r12
        push    r13
        push    r14
        push    r15
        mov     [rdi], rsp
        mov     rsp, rsi
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbx
        pop     rbp
        ret

# Freestanding memory primitives (GCC emits calls to these).
        .global memcpy
memcpy:
        mov     rax, rdi
        mov     rcx, rdx
        rep movsb
        ret

        .global memset
memset:
        mov     r8, rdi
        mov     eax, esi
        mov     rcx, rdx
        rep stosb
        mov     rax, r8
        ret

        .global memmove
memmove:
        mov     rax, rdi
        mov     rcx, rdx
        cmp     rdi, rsi
        jbe     1f
        lea     r8, [rsi + rdx]
        cmp     rdi, r8
        jae     1f
        std
        lea     rsi, [rsi + rdx - 1]
        lea     rdi, [rdi + rdx - 1]
        rep movsb
        cld
        ret
1:      rep movsb
        ret

        .section .note.GNU-stack, "", @progbits