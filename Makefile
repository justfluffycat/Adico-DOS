# Adico DOS build: gcc + GNU as + GNU ld. QEMU is only needed to run it.
CC      := gcc
LD      := ld
OBJCOPY := objcopy
QEMU    := qemu-system-x86_64
SHELL   := /bin/bash

CFLAGS  := -m64 -ffreestanding -fno-pie -no-pie -mno-red-zone -mgeneral-regs-only \
           -fno-stack-protector -fno-asynchronous-unwind-tables \
           -fno-tree-loop-distribute-patterns -O2 -Wall -Wextra -std=gnu11

define LDSCRIPT
ENTRY(_start)
SECTIONS
{
  . = 1M;
  .text   : ALIGN(4K) { KEEP(*(.multiboot)) *(.text .text.*) }
  .rodata : ALIGN(4K) { *(.rodata .rodata.*) }
  .data   : ALIGN(4K) { *(.data .data.*) }
  .bss    : ALIGN(4K) { *(.bootbss) . = ALIGN(16); __bss_start = .; *(.bss .bss.* COMMON) __bss_end = .; }
  . = ALIGN(4K);
  __kernel_end = .;
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
endef

all: adico.elf adico32.elf adico.img

adico.ld:
	$(file >$@,$(LDSCRIPT))

adico_boot.o: adico_boot.S
	$(CC) -c $< -o $@

adico_kernel.o: adico_kernel.c
	$(CC) $(CFLAGS) -c $< -o $@

adico_posix.o: adico_posix.c
	$(CC) $(CFLAGS) -Wno-unused-parameter -c $< -o $@

adico.elf: adico.ld adico_boot.o adico_kernel.o adico_posix.o
	$(LD) -nostdlib -static -z max-page-size=0x1000 -T adico.ld -o $@ adico_boot.o adico_kernel.o adico_posix.o

# QEMU's -kernel loader only accepts 32-bit ELF images for Multiboot, so the
# 64-bit image is re-wrapped. Entry code and header are 32-bit; nothing changes.
adico32.elf: adico.elf
	$(OBJCOPY) -O elf32-i386 $< $@

adico.img:
	dd if=/dev/zero of=$@ bs=1M count=8 2>/dev/null

run: all
	$(QEMU) -kernel adico32.elf -m 128M -drive file=adico.img,format=raw,if=ide -nographic

run-gui: all
	$(QEMU) -kernel adico32.elf -m 128M -drive file=adico.img,format=raw,if=ide -serial stdio

iso: adico32.elf
	mkdir -p iso/boot/grub
	cp adico32.elf iso/boot/adico32.elf
	printf 'menuentry "Adico DOS" {\n  multiboot /boot/adico32.elf\n  boot\n}\n' > iso/boot/grub/grub.cfg
	grub-mkrescue -o adico.iso iso

abi-check:
	@diff <(sed -n '/BEGIN SHARED ABI/,/END SHARED ABI/p' adico_kernel.c) \
	      <(sed -n '/BEGIN SHARED ABI/,/END SHARED ABI/p' adico_posix.c) && echo "ABI blocks identical"

# Smoke test: boots in QEMU, feeds a few commands through the serial console.
test: all
	@( sleep 4; echo 'echo smoke-test-ok'; sleep 1; echo 'uname -a'; sleep 1; \
	   echo 'ls /bin | wc -l'; sleep 1; echo 'poweroff' ) | \
	  timeout 30 $(QEMU) -kernel adico32.elf -m 128M -drive file=adico.img,format=raw,if=ide -nographic -no-reboot \
	  | tee /tmp/adico-test.log; grep -q smoke-test-ok /tmp/adico-test.log && echo "SMOKE TEST PASSED"

lines:
	@wc -l adico_boot.S adico_kernel.c adico_posix.c

clean:
	rm -rf *.o adico.ld adico.elf adico32.elf adico.iso iso

.PHONY: all run run-gui iso test abi-check lines clean