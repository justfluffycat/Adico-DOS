/*
 * adico_kernel.c -- Adico DOS kernel (x86_64, long mode)
 *
 * One file, in this order:
 *   1. shared ABI           6. ATA PIO disk driver      11. system calls
 *   2. library core         7. tasks, signals, sched    12. disk snapshot
 *   3. heap allocator       8. TTY line discipline      13. traps and IRQs
 *   4. console (VGA/COM1)   9. RAM file system (VFS)    14. kmain
 *   5. clock (PIT/RTC)     10. pipes
 *
 * Every program runs as a cooperative kernel task with its own stack and a
 * private file-descriptor table. Programs reach the kernel only through the
 * Linux-style "int 0x80" system call interface defined by the shared ABI.
 */
/* ===== BEGIN SHARED ABI (keep byte-identical in adico_kernel.c and adico_posix.c) ===== */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;
typedef long i64;
typedef u64 size_t;
typedef i64 ssize_t;
typedef i64 off_t;
typedef i64 time_t;
typedef int pid_t;
typedef u32 mode_t;
typedef __builtin_va_list va_list;
#define va_start(v, l) __builtin_va_start(v, l)
#define va_end(v) __builtin_va_end(v)
#define va_arg(v, t) __builtin_va_arg(v, t)
#define NULL ((void *)0)
#define HZ 100
#define NAME_MAX 55
#define PATH_MAX 256
#define OPEN_MAX 16

/* errno values (Linux numbering) */
enum { EPERM = 1, ENOENT = 2, ESRCH = 3, EINTR = 4, EIO = 5, ENOEXEC = 8, EBADF = 9,
       ECHILD = 10, EAGAIN = 11, ENOMEM = 12, EACCES = 13, EFAULT = 14, EBUSY = 16,
       EEXIST = 17, ENODEV = 19, ENOTDIR = 20, EISDIR = 21, EINVAL = 22, EMFILE = 24,
       ENOTTY = 25, EFBIG = 27, ENOSPC = 28, ESPIPE = 29, EPIPE = 32, ERANGE = 34,
       ENAMETOOLONG = 36, ENOSYS = 38, ENOTEMPTY = 39 };

/* open(2) flags and file mode bits */
enum { O_RDONLY = 0, O_WRONLY = 1, O_RDWR = 2, O_ACCMODE = 3, O_CREAT = 0100,
       O_EXCL = 0200, O_TRUNC = 01000, O_APPEND = 02000, O_DIRECTORY = 0200000 };
enum { S_IFMT = 0170000, S_IFDIR = 0040000, S_IFCHR = 0020000, S_IFREG = 0100000 };
enum { SEEK_SET = 0, SEEK_CUR = 1, SEEK_END = 2 };

/* signals */
enum { SIGHUP = 1, SIGINT = 2, SIGQUIT = 3, SIGILL = 4, SIGABRT = 6, SIGFPE = 8,
       SIGKILL = 9, SIGSEGV = 11, SIGPIPE = 13, SIGTERM = 15, SIGCHLD = 17, NSIG = 32 };
#define SIG_DFL 0L
#define SIG_IGN 1L
#define WNOHANG 1
#define WIFEXITED(s) (((s) & 0x7f) == 0)
#define WEXITSTATUS(s) (((s) >> 8) & 0xff)
#define WTERMSIG(s) ((s) & 0x7f)
#define TIOCGPGRP 0x540F
#define TIOCSPGRP 0x5410

/* system call numbers (Linux x86_64 numbering where one exists) */
enum { SYS_read = 0, SYS_write = 1, SYS_open = 2, SYS_close = 3, SYS_stat = 4, SYS_fstat = 5,
       SYS_lseek = 8, SYS_mmap = 9, SYS_munmap = 11, SYS_ioctl = 16, SYS_pipe = 22,
       SYS_dup = 32, SYS_dup2 = 33, SYS_nanosleep = 35, SYS_getpid = 39, SYS_signal = 48,
       SYS_exit = 60, SYS_wait4 = 61, SYS_kill = 62, SYS_uname = 63, SYS_getdents = 78,
       SYS_getcwd = 79, SYS_chdir = 80, SYS_rename = 82, SYS_mkdir = 83, SYS_rmdir = 84,
       SYS_unlink = 87, SYS_chmod = 90, SYS_sysinfo = 99, SYS_setpgid = 109,
       SYS_getppid = 110, SYS_getpgid = 121, SYS_sync = 162, SYS_reboot = 169,
       SYS_time = 201, SYS_spawn = 500, SYS_procinfo = 501 };

struct stat { u64 st_ino; u32 st_mode; u32 st_nlink; i64 st_size; i64 st_mtime; };
struct dirent { u64 d_ino; u32 d_type; char d_name[NAME_MAX + 1]; };
struct utsname { char sysname[32], nodename[32], release[32], version[32], machine[32]; };
struct timespec { time_t tv_sec; long tv_nsec; };
struct sysinfo { u64 uptime_ticks, mem_total, mem_free, nprocs, fs_nodes, fs_bytes, disk_sectors; };
struct spawn_attr { int fd[3]; int pgid; };          /* pgid: >0 join, <0 new group, 0 inherit */
struct pinfo { int pid, ppid, pgid, state; char name[16]; };   /* state: 1 run, 2 sleep, 3 zombie */
struct prog { const char *name; int (*main)(int, char **, char **); };
/* ===== END SHARED ABI ===== */

#define NORETURN __attribute__((noreturn))
#define PACKED __attribute__((packed))

/* ---- provided by adico_boot.S ---- */
extern void port_outb(u16 port, u8 val);
extern u8 port_inb(u16 port);
extern void port_outw(u16 port, u16 val);
extern u16 port_inw(u16 port);
extern u64 irq_save(void);
extern void irq_restore(u64 flags);
extern void cpu_sti(void);
extern void cpu_cli(void);
extern void cpu_halt(void);
extern u64 cpu_cr2(void);
extern u64 rdtsc_read(void);
extern void idt_load(const void *idtr);
extern void ctx_switch(u64 *old_sp, u64 new_sp);
extern u64 isr_stub_table[48];
extern void isr_stub_128(void);
extern char __kernel_end[];
void *memcpy(void *d, const void *s, size_t n);
void *memset(void *d, int c, size_t n);
void *memmove(void *d, const void *s, size_t n);

/* ---- provided by adico_posix.c ---- */
extern const struct prog posix_progs[];
extern int posix_init_main(int argc, char **argv, char **envp);

/* =========================================================================
 * 2. LIBRARY CORE (shared with the POSIX layer at link time)
 * ========================================================================= */
int memcmp(const void *a, const void *b, size_t n)
{
    const u8 *x = a, *y = b;
    for (; n; n--, x++, y++)
        if (*x != *y)
            return *x - *y;
    return 0;
}

size_t strlen(const char *s)
{
    size_t n = 0;
    while (s[n])
        n++;
    return n;
}

int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return (u8)*a - (u8)*b;
}

int strncmp(const char *a, const char *b, size_t n)
{
    while (n && *a && *a == *b) {
        a++;
        b++;
        n--;
    }
    return n ? (u8)*a - (u8)*b : 0;
}

char *strchr(const char *s, int c)
{
    for (;; s++) {
        if (*s == (char)c)
            return (char *)s;
        if (!*s)
            return NULL;
    }
}

char *strcpy(char *d, const char *s)
{
    char *r = d;
    while ((*d++ = *s++))
        ;
    return r;
}

char *strncpy(char *d, const char *s, size_t n)
{
    size_t i = 0;
    for (; i < n && s[i]; i++)
        d[i] = s[i];
    for (; i < n; i++)
        d[i] = 0;
    return d;
}

static int fmt_u64(char *out, u64 v, unsigned base, int upper)
{
    char tmp[24];
    const char *dig = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    int n = 0, len = 0;
    do {
        tmp[n++] = dig[v % base];
        v /= base;
    } while (v);
    while (n)
        out[len++] = tmp[--n];
    return len;
}

/* Subset of C99: flags '-' '0', width, '.precision' (strings), length l/ll/z,
 * conversions d i u x X p s c %. */
int vsnprintf(char *buf, size_t n, const char *fmt, va_list ap)
{
    size_t pos = 0;
#define PUT(ch) do { if (pos + 1 < n) buf[pos] = (ch); pos++; } while (0)
    for (; *fmt; fmt++) {
        if (*fmt != '%') {
            PUT(*fmt);
            continue;
        }
        fmt++;
        int left = 0, zero = 0, width = 0, prec = -1, lng = 0, pfx = 0, numeric = 0;
        char sign = 0, tmp[24];
        const char *s = tmp;
        int len = 0;
        for (;; fmt++) {
            if (*fmt == '-')
                left = 1;
            else if (*fmt == '0')
                zero = 1;
            else
                break;
        }
        if (*fmt == '*') {
            width = va_arg(ap, int);
            if (width < 0) {
                left = 1;
                width = -width;
            }
            fmt++;
        } else {
            while (*fmt >= '0' && *fmt <= '9')
                width = width * 10 + (*fmt++ - '0');
        }
        if (*fmt == '.') {
            fmt++;
            prec = 0;
            if (*fmt == '*') {
                prec = va_arg(ap, int);
                fmt++;
            } else {
                while (*fmt >= '0' && *fmt <= '9')
                    prec = prec * 10 + (*fmt++ - '0');
            }
        }
        while (*fmt == 'l' || *fmt == 'z') {
            lng++;
            fmt++;
        }
        switch (*fmt) {
        case 'c':
            tmp[0] = (char)va_arg(ap, int);
            len = 1;
            break;
        case 's':
            s = va_arg(ap, const char *);
            if (!s)
                s = "(null)";
            while (s[len] && (prec < 0 || len < prec))
                len++;
            break;
        case 'd':
        case 'i': {
            i64 v = lng ? va_arg(ap, i64) : va_arg(ap, int);
            u64 u = v < 0 ? -(u64)v : (u64)v;
            if (v < 0)
                sign = '-';
            len = fmt_u64(tmp, u, 10, 0);
            numeric = 1;
            break;
        }
        case 'u':
        case 'o':
        case 'x':
        case 'X':
        case 'p': {
            u64 v = (lng || *fmt == 'p') ? va_arg(ap, u64) : va_arg(ap, u32);
            len = fmt_u64(tmp, v, *fmt == 'u' ? 10 : *fmt == 'o' ? 8 : 16, *fmt == 'X');
            pfx = (*fmt == 'p');
            numeric = 1;
            break;
        }
        case '%':
            tmp[0] = '%';
            len = 1;
            break;
        case 0:
            goto done;
        default:
            tmp[0] = '%';
            tmp[1] = *fmt;
            len = 2;
            break;
        }
        int plen = (sign ? 1 : 0) + (pfx ? 2 : 0);
        int pad = width > len + plen ? width - len - plen : 0;
        if (!left && !(zero && numeric))
            while (pad-- > 0)
                PUT(' ');
        if (sign)
            PUT(sign);
        if (pfx) {
            PUT('0');
            PUT('x');
        }
        if (!left && zero && numeric)
            while (pad-- > 0)
                PUT('0');
        for (int i = 0; i < len; i++)
            PUT(s[i]);
        if (left)
            while (pad-- > 0)
                PUT(' ');
    }
done:
    if (n)
        buf[pos < n ? pos : n - 1] = 0;
#undef PUT
    return (int)pos;
}

int snprintf(char *buf, size_t n, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(buf, n, fmt, ap);
    va_end(ap);
    return r;
}

/* =========================================================================
 * 3. HEAP ALLOCATOR (first fit, implicit list, forward coalescing)
 * ========================================================================= */
struct hblk {
    u64 size;
    u64 used;
};
static u8 *heap_lo, *heap_hi;

static void heap_init(u64 start, u64 end)
{
    heap_lo = (u8 *)((start + 15) & ~15UL);
    heap_hi = (u8 *)(end & ~15UL);
    struct hblk *b = (struct hblk *)heap_lo;
    b->size = (u64)(heap_hi - heap_lo) - sizeof *b;
    b->used = 0;
}

static struct hblk *hnext(struct hblk *b)
{
    return (struct hblk *)((u8 *)(b + 1) + b->size);
}

static void heap_coalesce(void)
{
    struct hblk *b = (struct hblk *)heap_lo;
    while ((u8 *)b < heap_hi) {
        struct hblk *n = hnext(b);
        if (!b->used && (u8 *)n < heap_hi && !n->used)
            b->size += sizeof *n + n->size;
        else
            b = n;
    }
}

void *kmalloc(size_t n)
{
    n = (n + 15) & ~15UL;
    if (!n)
        n = 16;
    for (int pass = 0; pass < 2; pass++) {
        for (struct hblk *b = (struct hblk *)heap_lo; (u8 *)b < heap_hi; b = hnext(b)) {
            if (b->used || b->size < n)
                continue;
            if (b->size >= n + sizeof *b + 16) {
                struct hblk *r = (struct hblk *)((u8 *)(b + 1) + n);
                r->size = b->size - n - sizeof *r;
                r->used = 0;
                b->size = n;
            }
            b->used = 1;
            return b + 1;
        }
        heap_coalesce();
    }
    return NULL;
}

void kfree(void *p)
{
    if (!p)
        return;
    struct hblk *b = (struct hblk *)p - 1, *n;
    b->used = 0;
    n = hnext(b);
    if ((u8 *)n < heap_hi && !n->used)
        b->size += sizeof *n + n->size;
}

void *kcalloc(size_t a, size_t b)
{
    void *p = kmalloc(a * b);
    if (p)
        memset(p, 0, a * b);
    return p;
}

void *krealloc(void *p, size_t n)
{
    if (!p)
        return kmalloc(n);
    size_t old = ((struct hblk *)p - 1)->size;
    if (n <= old)
        return p;
    void *q = kmalloc(n);
    if (!q)
        return NULL;
    memcpy(q, p, old);
    kfree(p);
    return q;
}

static u64 heap_free_bytes(void)
{
    u64 t = 0;
    for (struct hblk *b = (struct hblk *)heap_lo; (u8 *)b < heap_hi; b = hnext(b))
        if (!b->used)
            t += b->size;
    return t;
}

/* =========================================================================
 * 4. CONSOLE: COM1 serial + VGA text mode, kernel printf
 * ========================================================================= */
#define COM1 0x3F8

static void serial_init(void)
{
    port_outb(COM1 + 1, 0x00);          /* interrupts off while programming */
    port_outb(COM1 + 3, 0x80);          /* DLAB on */
    port_outb(COM1 + 0, 0x01);          /* divisor 1 = 115200 baud */
    port_outb(COM1 + 1, 0x00);
    port_outb(COM1 + 3, 0x03);          /* 8N1 */
    port_outb(COM1 + 2, 0xC7);          /* enable and clear FIFOs */
    port_outb(COM1 + 4, 0x0B);          /* DTR, RTS, OUT2 (IRQ gate) */
    port_outb(COM1 + 1, 0x01);          /* receive interrupt */
}

static void serial_putc(char c)
{
    for (u32 t = 100000; t && !(port_inb(COM1 + 5) & 0x20); t--)
        ;
    port_outb(COM1, (u8)c);
}

static volatile u16 *const VGA = (volatile u16 *)0xB8000;
static int vx, vy, vesc, vnp, vpar[2];

static void vga_cursor(void)
{
    u16 p = (u16)(vy * 80 + vx);
    port_outb(0x3D4, 14);
    port_outb(0x3D5, (u8)(p >> 8));
    port_outb(0x3D4, 15);
    port_outb(0x3D5, (u8)(p & 0xFF));
}

static void vga_clear(void)
{
    for (int i = 0; i < 80 * 25; i++)
        VGA[i] = 0x0720;
    vx = vy = 0;
}

static void vga_putc(char c)
{
    if (vesc == 1) {                    /* after ESC */
        if (c == '[') {
            vesc = 2;
            vnp = 0;
            vpar[0] = vpar[1] = 0;
        } else {
            vesc = 0;
        }
        return;
    }
    if (vesc == 2) {                    /* inside CSI: supports J, H, f; ignores the rest */
        if (c >= '0' && c <= '9') {
            vpar[vnp] = vpar[vnp] * 10 + (c - '0');
            return;
        }
        if (c == ';') {
            vnp = 1;
            return;
        }
        vesc = 0;
        if (c == 'J') {
            vga_clear();
        } else if (c == 'H' || c == 'f') {
            vy = vpar[0] > 0 ? vpar[0] - 1 : 0;
            vx = vpar[1] > 0 ? vpar[1] - 1 : 0;
            if (vy > 24)
                vy = 24;
            if (vx > 79)
                vx = 79;
        }
        vga_cursor();
        return;
    }
    switch (c) {
    case 27:
        vesc = 1;
        return;
    case '\n':
        vx = 0;
        vy++;
        break;
    case '\r':
        vx = 0;
        break;
    case '\b':
        if (vx)
            vx--;
        break;
    case '\t':
        vx = (vx + 8) & ~7;
        break;
    default:
        VGA[vy * 80 + vx] = (u16)(0x0700 | (u8)c);
        vx++;
    }
    if (vx >= 80) {
        vx = 0;
        vy++;
    }
    if (vy >= 25) {
        for (int i = 0; i < 80 * 24; i++)
            VGA[i] = VGA[i + 80];
        for (int i = 80 * 24; i < 80 * 25; i++)
            VGA[i] = 0x0720;
        vy = 24;
    }
    vga_cursor();
}

static void console_putc(char c)
{
    if (c == '\n')
        serial_putc('\r');
    serial_putc(c);
    vga_putc(c);
}

static void console_write(const char *s, size_t n)
{
    while (n--)
        console_putc(*s++);
}

static void kprintf(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n > (int)sizeof buf - 1)
        n = sizeof buf - 1;
    console_write(buf, (size_t)n);
}

/* =========================================================================
 * 5. CLOCK: PIT timer tick and CMOS real-time clock
 * ========================================================================= */
static volatile u64 ticks;
static i64 boot_epoch;

static u8 cmos_read(u8 reg)
{
    port_outb(0x70, reg);
    return port_inb(0x71);
}

static i64 days_from_civil(i64 y, u32 m, u32 d)
{
    y -= m <= 2;
    i64 era = (y >= 0 ? y : y - 399) / 400;
    u32 yoe = (u32)(y - era * 400);
    u32 doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    u32 doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (i64)doe - 719468;
}

static void rtc_init(void)
{
    for (int i = 0; i < 100000 && (cmos_read(0x0A) & 0x80); i++)
        ;
    u32 s = cmos_read(0), mi = cmos_read(2), h = cmos_read(4);
    u32 d = cmos_read(7), mo = cmos_read(8), y = cmos_read(9), b = cmos_read(0x0B);
    if (!(b & 4)) {                     /* BCD to binary */
        s = (s & 15) + (s >> 4) * 10;
        mi = (mi & 15) + (mi >> 4) * 10;
        h = ((h & 15) + ((h & 0x70) >> 4) * 10) | (h & 0x80);
        d = (d & 15) + (d >> 4) * 10;
        mo = (mo & 15) + (mo >> 4) * 10;
        y = (y & 15) + (y >> 4) * 10;
    }
    if (!(b & 2) && (h & 0x80))         /* 12-hour clock, PM flag */
        h = ((h & 0x7F) % 12) + 12;
    if (!d || !mo || mo > 12) {
        boot_epoch = 0;
        return;
    }
    boot_epoch = days_from_civil(2000 + y, mo, d) * 86400 + h * 3600 + mi * 60 + s;
}

static i64 time_now(void)
{
    return boot_epoch + (i64)(ticks / HZ);
}

static void pit_init(void)
{
    u32 div = 1193182 / HZ;
    port_outb(0x43, 0x36);
    port_outb(0x40, (u8)(div & 0xFF));
    port_outb(0x40, (u8)(div >> 8));
}

/* =========================================================================
 * 6. ATA PIO DISK DRIVER (primary bus, master, LBA28, polled)
 * ========================================================================= */
static u32 disk_sectors;

static void ata_delay(void)             /* ~400 ns: four reads of the alternate status register */
{
    for (int i = 0; i < 4; i++)
        port_inb(0x3F6);
}

static int ata_wait(int need_drq)
{
    for (int i = 0; i < 2000000; i++) {
        u8 s = port_inb(0x1F7);
        if (s & 0x80)                   /* BSY: other bits are not valid yet */
            continue;
        if (s & 0x21)                   /* ERR or DF */
            return -EIO;
        if (!need_drq || (s & 0x08))
            return 0;
    }
    return -EIO;
}

static void ata_init(void)
{
    u16 id[256];
    port_outb(0x3F6, 0x02);             /* nIEN: polled operation only */
    port_outb(0x1F6, 0xA0);
    for (int i = 0; i < 4; i++)
        port_inb(0x3F6);
    if (port_inb(0x1F7) == 0xFF)
        return;                         /* floating bus: no controller */
    port_outb(0x1F2, 0);
    port_outb(0x1F3, 0);
    port_outb(0x1F4, 0);
    port_outb(0x1F5, 0);
    port_outb(0x1F7, 0xEC);             /* IDENTIFY */
    ata_delay();
    if (port_inb(0x1F7) == 0)
        return;
    for (int i = 0; i < 2000000 && (port_inb(0x1F7) & 0x80); i++)
        ;
    if (port_inb(0x1F4) || port_inb(0x1F5))
        return;                         /* ATAPI or SATA signature */
    if (ata_wait(1))
        return;
    for (int i = 0; i < 256; i++)
        id[i] = port_inw(0x1F0);
    disk_sectors = (u32)id[60] | ((u32)id[61] << 16);
}

static int ata_rw(u32 lba, u16 *buf, int write)
{
    port_outb(0x1F6, (u8)(0xE0 | ((lba >> 24) & 0x0F)));
    port_outb(0x1F2, 1);
    port_outb(0x1F3, (u8)lba);
    port_outb(0x1F4, (u8)(lba >> 8));
    port_outb(0x1F5, (u8)(lba >> 16));
    port_outb(0x1F7, write ? 0x30 : 0x20);
    ata_delay();
    if (ata_wait(1))
        return -EIO;
    for (int i = 0; i < 256; i++) {
        if (write)
            port_outw(0x1F0, buf[i]);
        else
            buf[i] = port_inw(0x1F0);
    }
    if (write) {
        port_outb(0x1F7, 0xE7);         /* cache flush */
        ata_delay();
        return ata_wait(0);
    }
    return 0;
}

/* =========================================================================
 * 7. TASKS, SIGNALS AND THE COOPERATIVE SCHEDULER
 * ========================================================================= */
#define MAX_TASKS 32
#define STACK_SIZE 65536
enum { TS_FREE, TS_RUN, TS_SLEEP, TS_ZOMBIE };
enum { FK_INODE, FK_PIPE_R, FK_PIPE_W };

struct inode;
struct pipe;
struct file {
    int refs, kind, flags;
    off_t pos;
    struct inode *ino;
    struct pipe *pipe;
};
struct mnode {                          /* header of every mmap() block */
    struct mnode *prev, *next;
    u64 magic, pad;
};
struct task {
    int pid, ppid, pgid, state, status, argc;
    void *wchan;
    u32 sigpend, sigign;
    u64 sp;
    u8 *stack;
    struct file *fds[OPEN_MAX];
    struct inode *cwd;
    char name[16];
    char **argv, **envp;
    int (*entry)(int, char **, char **);
    struct mnode *allocs;
};

static struct task tasks[MAX_TASKS];    /* slot 0 is the boot context */
static struct task *cur = &tasks[0];
static int next_pid = 1;

static void file_put(struct file *f);
static void iput(struct inode *n);
static void system_off(int reboot, const char *why) NORETURN;
static int fs_save(void);

static void schedule(void);             /* caller must have interrupts disabled */

static void sleep_on(void *chan)
{
    cur->wchan = chan;
    cur->state = TS_SLEEP;
    schedule();
    cur->wchan = NULL;
}

static void wakeup(void *chan)
{
    for (int i = 1; i < MAX_TASKS; i++)
        if (tasks[i].state == TS_SLEEP && tasks[i].wchan == chan)
            tasks[i].state = TS_RUN;
}

static void schedule(void)
{
    struct task *prev = cur, *next = NULL;
    for (;;) {
        int start = (int)(prev - tasks);
        for (int i = 1; i <= MAX_TASKS; i++) {
            struct task *t = &tasks[(start + i) % MAX_TASKS];
            if (t != &tasks[0] && t->state == TS_RUN) {
                next = t;
                break;
            }
        }
        if (next)
            break;
        cpu_sti();                      /* idle until an interrupt wakes someone */
        cpu_halt();
        cpu_cli();
    }
    if (next != prev) {
        cur = next;
        ctx_switch(&prev->sp, next->sp);
    }
}

#define sig_pending(t) ((t)->sigpend != 0)

static void signal_send(struct task *t, int sig)
{
    if (sig <= 0 || sig >= NSIG || sig == SIGCHLD || t->state == TS_FREE || t->state == TS_ZOMBIE)
        return;
    if ((t->sigign & (1u << sig)) && sig != SIGKILL)
        return;
    t->sigpend |= 1u << sig;
    if (t->state == TS_SLEEP)
        t->state = TS_RUN;              /* interrupt the sleep; the caller sees EINTR */
}

static void signal_group(int pgid, int sig)
{
    if (pgid <= 0)
        return;
    for (int i = 1; i < MAX_TASKS; i++)
        if (tasks[i].state != TS_FREE && tasks[i].pgid == pgid)
            signal_send(&tasks[i], sig);
}

static NORETURN void task_exit(int status)
{
    cpu_cli();
    struct task *t = cur;
    for (int i = 0; i < OPEN_MAX; i++) {
        if (t->fds[i]) {
            file_put(t->fds[i]);
            t->fds[i] = NULL;
        }
    }
    if (t->cwd) {
        iput(t->cwd);
        t->cwd = NULL;
    }
    while (t->allocs) {
        struct mnode *m = t->allocs;
        t->allocs = m->next;
        kfree(m);
    }
    kfree(t->argv);
    kfree(t->envp);
    t->argv = t->envp = NULL;
    for (int i = 1; i < MAX_TASKS; i++) {       /* orphans are adopted by init */
        if (tasks[i].state != TS_FREE && tasks[i].ppid == t->pid) {
            tasks[i].ppid = 1;
            wakeup(&tasks[1]);
        }
    }
    t->status = status;
    t->state = TS_ZOMBIE;
    for (int i = 1; i < MAX_TASKS; i++)
        if (tasks[i].state != TS_FREE && tasks[i].pid == t->ppid)
            wakeup(&tasks[i]);
    if (t->pid == 1)
        system_off(0, "init exited");
    schedule();
    for (;;)
        cpu_halt();
}

static void signal_check(void)          /* default action of every signal: terminate */
{
    if (!cur->sigpend)
        return;
    int s = __builtin_ctz(cur->sigpend);
    cur->sigpend &= ~(1u << s);
    task_exit(s);
}

static void task_start(void)
{
    cpu_sti();                          /* we arrive here from schedule() with IF=0 */
    int rc = cur->entry(cur->argc, cur->argv, cur->envp);
    task_exit((rc & 0xFF) << 8);
}

/* argv/envp ownership passes to the new task (freed in task_exit). */
static struct task *task_create(const char *name, int (*entry)(int, char **, char **),
                                char **argv, char **envp, struct file *const fd[3],
                                struct inode *cwd, int pgid, struct task *parent);

static char **dup_strv(char *const *v)
{
    size_t n = 0, bytes = 0;
    if (v)
        for (; v[n]; n++)
            bytes += strlen(v[n]) + 1;
    char **out = kmalloc((n + 1) * sizeof(char *) + bytes);
    if (!out)
        return NULL;
    char *p = (char *)(out + n + 1);
    for (size_t i = 0; i < n; i++) {
        size_t l = strlen(v[i]) + 1;
        memcpy(p, v[i], l);
        out[i] = p;
        p += l;
    }
    out[n] = NULL;
    return out;
}

/* =========================================================================
 * 8. KEYBOARD AND TTY LINE DISCIPLINE (canonical mode, echo, ^C ^D ^U)
 * ========================================================================= */
static struct {
    char line[256];
    int llen, eof, intr, waiters, fg;
    u32 rh, rt;
    char ready[1024];
} tty;

static void tty_echo(const char *s)
{
    while (*s)
        console_putc(*s++);
}

static void tty_push(char c)
{
    if (tty.rt - tty.rh < sizeof tty.ready)
        tty.ready[tty.rt++ % sizeof tty.ready] = c;
}

static void tty_input(char c)           /* called from IRQ context */
{
    if (c == '\r')
        c = '\n';
    if (c == 3) {                       /* ^C */
        tty_echo("^C\n");
        tty.llen = 0;
        if (tty.waiters)
            tty.intr = 1;
        signal_group(tty.fg, SIGINT);
        wakeup(&tty);
        return;
    }
    if (c == 4) {                       /* ^D */
        if (tty.llen) {
            for (int i = 0; i < tty.llen; i++)
                tty_push(tty.line[i]);
            tty.llen = 0;
        } else if (tty.waiters) {
            tty.eof = 1;
        }
        wakeup(&tty);
        return;
    }
    if (c == 0x7F || c == '\b') {
        if (tty.llen) {
            tty.llen--;
            tty_echo("\b \b");
        }
        return;
    }
    if (c == 0x15) {                    /* ^U */
        while (tty.llen) {
            tty.llen--;
            tty_echo("\b \b");
        }
        return;
    }
    if (c == '\n') {
        for (int i = 0; i < tty.llen; i++)
            tty_push(tty.line[i]);
        tty_push('\n');
        tty.llen = 0;
        console_putc('\n');
        wakeup(&tty);
        return;
    }
    if ((c >= 32 && c < 127) || c == '\t') {
        if (tty.llen < (int)sizeof tty.line - 1) {
            tty.line[tty.llen++] = c;
            console_putc(c);
        }
    }
}

static ssize_t tty_read(char *buf, size_t n)
{
    u64 fl = irq_save();
    while (tty.rt == tty.rh) {
        if (tty.eof) {
            tty.eof = 0;
            irq_restore(fl);
            return 0;
        }
        if (tty.intr) {
            tty.intr = 0;
            irq_restore(fl);
            return -EINTR;
        }
        if (sig_pending(cur)) {
            irq_restore(fl);
            return -EINTR;
        }
        tty.waiters++;
        sleep_on(&tty);
        tty.waiters--;
    }
    size_t i = 0;
    while (i < n && tty.rt != tty.rh) {
        char c = tty.ready[tty.rh++ % sizeof tty.ready];
        buf[i++] = c;
        if (c == '\n')
            break;
    }
    irq_restore(fl);
    return (ssize_t)i;
}

static const char sc_lower[] =
    "\0\033" "1234567890-=\b\tqwertyuiop[]\n\0asdfghjkl;'`\0\\zxcvbnm,./\0*\0 ";
static const char sc_upper[] =
    "\0\033" "!@#$%^&*()_+\b\tQWERTYUIOP{}\n\0ASDFGHJKL:\"~\0|ZXCVBNM<>?\0*\0 ";

static void kbd_irq(void)
{
    static int shift, ctrl, caps, ext;
    u8 sc = port_inb(0x60);
    if (sc == 0xE0) {
        ext = 1;
        return;
    }
    int rel = sc & 0x80;
    sc &= 0x7F;
    if (ext) {                          /* arrow keys etc. are ignored */
        ext = 0;
        return;
    }
    if (sc == 0x2A || sc == 0x36) {
        shift = !rel;
        return;
    }
    if (sc == 0x1D) {
        ctrl = !rel;
        return;
    }
    if (rel)
        return;
    if (sc == 0x3A) {
        caps = !caps;
        return;
    }
    if (sc >= sizeof sc_lower - 1)
        return;
    char c = (shift ? sc_upper : sc_lower)[sc];
    if (!c)
        return;
    if (caps && c >= 'a' && c <= 'z')
        c -= 32;
    else if (caps && c >= 'A' && c <= 'Z' && shift)
        c += 32;
    if (ctrl && ((c | 32) >= 'a' && (c | 32) <= 'z'))
        c = (char)((c | 32) - 'a' + 1);
    tty_input(c);
}

static void serial_irq(void)
{
    while (port_inb(COM1 + 5) & 1)
        tty_input((char)port_inb(COM1));
}

/* =========================================================================
 * 9. RAM FILE SYSTEM (single mount at "/", POSIX path semantics)
 * ========================================================================= */
enum { DEV_NULL = 1, DEV_ZERO, DEV_TTY, DEV_RANDOM };

struct inode {
    u64 ino;
    u32 mode;
    int refs, unlinked, dev;
    i64 mtime;
    struct inode *parent, *kids, *next;
    char name[NAME_MAX + 1];
    u8 *data;
    size_t size, cap;
    int (*prog)(int, char **, char **);
};

#define ISDIR(n) (((n)->mode & S_IFMT) == S_IFDIR)
#define ISREG(n) (((n)->mode & S_IFMT) == S_IFREG)
#define ISCHR(n) (((n)->mode & S_IFMT) == S_IFCHR)

static struct inode *root;
static u64 next_ino = 1, fs_nodes, fs_bytes;

static struct inode *inode_new(u32 mode)
{
    struct inode *n = kcalloc(1, sizeof *n);
    if (!n)
        return NULL;
    n->ino = next_ino++;
    n->mode = mode;
    n->mtime = time_now();
    fs_nodes++;
    return n;
}

static void inode_free(struct inode *n)
{
    fs_bytes -= n->cap;
    fs_nodes--;
    kfree(n->data);
    kfree(n);
}

static void iput(struct inode *n)
{
    if (--n->refs <= 0 && n->unlinked)
        inode_free(n);
}

static struct inode *dir_find(struct inode *d, const char *name, size_t len)
{
    for (struct inode *k = d->kids; k; k = k->next)
        if (strlen(k->name) == len && !memcmp(k->name, name, len))
            return k;
    return NULL;
}

static void dir_link(struct inode *d, struct inode *n, const char *name)
{
    strncpy(n->name, name, NAME_MAX);
    n->name[NAME_MAX] = 0;
    n->parent = d;
    struct inode **pp = &d->kids;
    while (*pp && strcmp((*pp)->name, n->name) < 0)
        pp = &(*pp)->next;
    n->next = *pp;
    *pp = n;
    d->mtime = time_now();
}

static void dir_unlink(struct inode *n)
{
    struct inode **pp = &n->parent->kids;
    while (*pp != n)
        pp = &(*pp)->next;
    *pp = n->next;
    n->parent->mtime = time_now();
    n->next = NULL;
    n->parent = NULL;
}

static void node_remove(struct inode *n)
{
    dir_unlink(n);
    n->unlinked = 1;
    if (n->refs <= 0)
        inode_free(n);
}

/* Resolve PATH. On success *node is the target (NULL if only the last
 * component is missing), *parent its directory and LEAF the last component. */
static int namei(struct inode *start, const char *path, struct inode **parent, char *leaf,
                 struct inode **node)
{
    struct inode *d = (*path == '/') ? root : start;
    const char *p = path;
    if (!*p)
        return -ENOENT;
    for (;;) {
        while (*p == '/')
            p++;
        if (!*p) {
            *parent = d->parent ? d->parent : d;
            *node = d;
            leaf[0] = 0;
            return 0;
        }
        const char *e = p;
        while (*e && *e != '/')
            e++;
        size_t len = (size_t)(e - p);
        if (len > NAME_MAX)
            return -ENAMETOOLONG;
        const char *q = e;
        while (*q == '/')
            q++;
        if (!ISDIR(d))
            return -ENOTDIR;
        struct inode *child;
        if (len == 1 && p[0] == '.')
            child = d;
        else if (len == 2 && p[0] == '.' && p[1] == '.')
            child = d->parent ? d->parent : d;
        else
            child = dir_find(d, p, len);
        if (!*q) {
            *parent = d;
            memcpy(leaf, p, len);
            leaf[len] = 0;
            *node = child;
            return 0;
        }
        if (!child)
            return -ENOENT;
        d = child;
        p = q;
    }
}

static int lookup(struct inode *start, const char *path, struct inode **out)
{
    struct inode *par;
    char leaf[NAME_MAX + 1];
    int r = namei(start, path, &par, leaf, out);
    if (r)
        return r;
    return *out ? 0 : -ENOENT;
}

static int vfs_create(struct inode *start, const char *path, u32 mode, struct inode **out)
{
    struct inode *par, *n;
    char leaf[NAME_MAX + 1];
    int r = namei(start, path, &par, leaf, &n);
    if (r)
        return r;
    if (n)
        return -EEXIST;
    n = inode_new(mode);
    if (!n)
        return -ENOMEM;
    dir_link(par, n, leaf);
    if (out)
        *out = n;
    return 0;
}

static int node_reserve(struct inode *n, size_t need)
{
    if (need <= n->cap)
        return 0;
    if (need > (64u << 20))
        return -EFBIG;
    size_t nc = n->cap ? n->cap : 64;
    while (nc < need)
        nc *= 2;
    u8 *p = krealloc(n->data, nc);
    if (!p)
        return -ENOSPC;
    memset(p + n->cap, 0, nc - n->cap);
    fs_bytes += nc - n->cap;
    n->data = p;
    n->cap = nc;
    return 0;
}

static ssize_t node_write(struct inode *n, off_t pos, const void *buf, size_t len)
{
    if (pos < 0)
        return -EINVAL;
    int r = node_reserve(n, (size_t)pos + len);
    if (r)
        return r;
    memcpy(n->data + pos, buf, len);
    if ((size_t)pos + len > n->size)
        n->size = (size_t)pos + len;
    n->mtime = time_now();
    return (ssize_t)len;
}

static void node_truncate(struct inode *n)
{
    if (n->data)
        memset(n->data, 0, n->size);
    n->size = 0;
    n->mtime = time_now();
}

static int cwd_path(struct inode *n, char *buf, size_t size)
{
    char tmp[PATH_MAX];
    size_t p = PATH_MAX - 1;
    tmp[p] = 0;
    while (n != root) {
        size_t l = strlen(n->name);
        if (l + 1 > p)
            return -ERANGE;
        p -= l;
        memcpy(tmp + p, n->name, l);
        tmp[--p] = '/';
        n = n->parent;
    }
    if (p == PATH_MAX - 1)
        tmp[--p] = '/';
    size_t len = strlen(tmp + p);
    if (len + 1 > size)
        return -ERANGE;
    memcpy(buf, tmp + p, len + 1);
    return (int)len + 1;
}

/* ---- devices ---- */
static u64 rng_state = 0x9E3779B97F4A7C15UL;

static u64 rng_next(void)
{
    u64 x = rng_state ^ rdtsc_read();
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x ? x : 1;
    return rng_state;
}

static ssize_t dev_read(struct inode *n, void *buf, size_t len)
{
    switch (n->dev) {
    case DEV_ZERO:
        memset(buf, 0, len);
        return (ssize_t)len;
    case DEV_RANDOM:
        for (size_t i = 0; i < len; i++)
            ((u8 *)buf)[i] = (u8)(rng_next() >> 24);
        return (ssize_t)len;
    case DEV_TTY:
        return tty_read(buf, len);
    default:
        return 0;
    }
}

static ssize_t dev_write(struct inode *n, const void *buf, size_t len)
{
    if (n->dev == DEV_TTY)
        console_write(buf, len);
    return (ssize_t)len;
}

/* =========================================================================
 * 10. PIPES AND OPEN FILE DESCRIPTIONS
 * ========================================================================= */
#define PIPE_SIZE 4096
struct pipe {
    int readers, writers;
    u32 head, len;
    u8 buf[PIPE_SIZE];
};

static ssize_t pipe_read(struct pipe *p, u8 *buf, size_t n)
{
    u64 fl = irq_save();
    while (p->len == 0) {
        if (p->writers == 0) {
            irq_restore(fl);
            return 0;                   /* EOF */
        }
        if (sig_pending(cur)) {
            irq_restore(fl);
            return -EINTR;
        }
        sleep_on(p);
    }
    irq_restore(fl);
    size_t k = n < p->len ? n : p->len;
    for (size_t i = 0; i < k; i++)
        buf[i] = p->buf[(p->head + i) % PIPE_SIZE];
    p->head = (p->head + (u32)k) % PIPE_SIZE;
    p->len -= (u32)k;
    wakeup(p);
    return (ssize_t)k;
}

static ssize_t pipe_write(struct pipe *p, const u8 *buf, size_t n)
{
    size_t done = 0;
    while (done < n) {
        if (p->readers == 0) {
            signal_send(cur, SIGPIPE);
            return done ? (ssize_t)done : -EPIPE;
        }
        u64 fl = irq_save();
        while (p->len == PIPE_SIZE && p->readers) {
            if (sig_pending(cur)) {
                irq_restore(fl);
                return done ? (ssize_t)done : -EINTR;
            }
            sleep_on(p);
        }
        irq_restore(fl);
        if (p->readers == 0)
            continue;
        size_t k = n - done;
        if (k > PIPE_SIZE - p->len)
            k = PIPE_SIZE - p->len;
        for (size_t i = 0; i < k; i++)
            p->buf[(p->head + p->len + i) % PIPE_SIZE] = buf[done + i];
        p->len += (u32)k;
        done += k;
        wakeup(p);
    }
    return (ssize_t)done;
}

static struct file *file_new(int kind, int flags)
{
    struct file *f = kcalloc(1, sizeof *f);
    if (f) {
        f->refs = 1;
        f->kind = kind;
        f->flags = flags;
    }
    return f;
}

static void file_put(struct file *f)
{
    if (--f->refs > 0)
        return;
    if (f->kind == FK_INODE) {
        iput(f->ino);
    } else {
        struct pipe *p = f->pipe;
        if (f->kind == FK_PIPE_R)
            p->readers--;
        else
            p->writers--;
        wakeup(p);
        if (!p->readers && !p->writers)
            kfree(p);
    }
    kfree(f);
}

static ssize_t file_read(struct file *f, void *buf, size_t n)
{
    if (f->kind == FK_PIPE_R)
        return pipe_read(f->pipe, buf, n);
    if (f->kind != FK_INODE || (f->flags & O_ACCMODE) == O_WRONLY)
        return -EBADF;
    struct inode *ino = f->ino;
    if (ISDIR(ino))
        return -EISDIR;
    if (ISCHR(ino))
        return dev_read(ino, buf, n);
    if (f->pos >= (off_t)ino->size)
        return 0;
    size_t k = ino->size - (size_t)f->pos;
    if (k > n)
        k = n;
    memcpy(buf, ino->data + f->pos, k);
    f->pos += (off_t)k;
    return (ssize_t)k;
}

static ssize_t file_write(struct file *f, const void *buf, size_t n)
{
    if (f->kind == FK_PIPE_W)
        return pipe_write(f->pipe, buf, n);
    if (f->kind != FK_INODE || (f->flags & O_ACCMODE) == O_RDONLY)
        return -EBADF;
    struct inode *ino = f->ino;
    if (ISDIR(ino))
        return -EISDIR;
    if (ISCHR(ino))
        return dev_write(ino, buf, n);
    if (f->flags & O_APPEND)
        f->pos = (off_t)ino->size;
    ssize_t r = node_write(ino, f->pos, buf, n);
    if (r > 0)
        f->pos += r;
    return r;
}

static struct file *fd_get(int fd)
{
    return (fd >= 0 && fd < OPEN_MAX) ? cur->fds[fd] : NULL;
}

static int fd_alloc(struct file *f)
{
    for (int i = 0; i < OPEN_MAX; i++) {
        if (!cur->fds[i]) {
            cur->fds[i] = f;
            return i;
        }
    }
    return -EMFILE;
}

static struct task *task_create(const char *name, int (*entry)(int, char **, char **),
                                char **argv, char **envp, struct file *const fd[3],
                                struct inode *cwd, int pgid, struct task *parent)
{
    int slot;
    for (slot = 1; slot < MAX_TASKS; slot++)
        if (tasks[slot].state == TS_FREE)
            break;
    if (slot == MAX_TASKS)
        return NULL;
    u8 *stack = kmalloc(STACK_SIZE);
    if (!stack)
        return NULL;
    struct task *t = &tasks[slot];
    memset(t, 0, sizeof *t);
    t->pid = next_pid++;
    t->ppid = parent ? parent->pid : 0;
    t->pgid = pgid > 0 ? pgid : (pgid < 0 ? t->pid : (parent ? parent->pgid : t->pid));
    strncpy(t->name, name, sizeof t->name - 1);
    t->entry = entry;
    t->argv = argv;
    t->envp = envp;
    for (t->argc = 0; argv[t->argc]; t->argc++)
        ;
    t->cwd = cwd;
    cwd->refs++;
    for (int i = 0; i < 3; i++) {
        fd[i]->refs++;
        t->fds[i] = fd[i];
    }
    t->stack = stack;
    u64 *top = (u64 *)(((u64)stack + STACK_SIZE) & ~15UL);
    top[-1] = 0;                        /* fake return address for task_start */
    top[-2] = (u64)task_start;          /* "returned" to by ctx_switch */
    for (int i = 3; i <= 8; i++)
        top[-i] = 0;                    /* r15 r14 r13 r12 rbx rbp */
    t->sp = (u64)&top[-8];
    t->state = TS_RUN;
    return t;
}

/* =========================================================================
 * 11. SYSTEM CALLS (int 0x80; rax = number, rdi rsi rdx r10 r8 r9 = arguments)
 * ========================================================================= */
struct regs {
    u64 r15, r14, r13, r12, r11, r10, r9, r8, rbp, rdi, rsi, rdx, rcx, rbx, rax;
    u64 vec, err, rip, cs, rflags, rsp, ss;
};

static char tick_chan;

static void fill_stat(struct stat *st, struct inode *n)
{
    st->st_ino = n->ino;
    st->st_mode = n->mode;
    st->st_size = ISREG(n) ? (i64)n->size : 0;
    st->st_mtime = n->mtime;
    st->st_nlink = 1;
    if (ISDIR(n)) {
        st->st_nlink = 2;
        for (struct inode *k = n->kids; k; k = k->next)
            if (ISDIR(k))
                st->st_nlink++;
    }
}

static i64 sys_open(const char *path, int flags, u32 mode)
{
    struct inode *par, *n;
    char leaf[NAME_MAX + 1];
    if (!path)
        return -EFAULT;
    int r = namei(cur->cwd, path, &par, leaf, &n);
    if (r)
        return r;
    int acc = flags & O_ACCMODE;
    if (!n) {
        if (!(flags & O_CREAT))
            return -ENOENT;
        n = inode_new(S_IFREG | (mode & 0777 & ~022u));
        if (!n)
            return -ENOMEM;
        dir_link(par, n, leaf);
    } else if ((flags & O_CREAT) && (flags & O_EXCL)) {
        return -EEXIST;
    }
    if (ISDIR(n) && acc != O_RDONLY)
        return -EISDIR;
    if ((flags & O_DIRECTORY) && !ISDIR(n))
        return -ENOTDIR;
    if (ISREG(n)) {
        if ((acc != O_WRONLY && !(n->mode & 0400)) || (acc != O_RDONLY && !(n->mode & 0200)))
            return -EACCES;
        if ((flags & O_TRUNC) && acc != O_RDONLY)
            node_truncate(n);
    }
    struct file *f = file_new(FK_INODE, flags);
    if (!f)
        return -ENOMEM;
    f->ino = n;
    n->refs++;
    int fd = fd_alloc(f);
    if (fd < 0)
        file_put(f);
    return fd;
}

static i64 sys_close(int fd)
{
    struct file *f = fd_get(fd);
    if (!f)
        return -EBADF;
    cur->fds[fd] = NULL;
    file_put(f);
    return 0;
}

static i64 sys_lseek(int fd, off_t off, int whence)
{
    struct file *f = fd_get(fd);
    if (!f)
        return -EBADF;
    if (f->kind != FK_INODE || ISCHR(f->ino))
        return -ESPIPE;
    off_t base = whence == SEEK_SET ? 0 : whence == SEEK_CUR ? f->pos : (off_t)f->ino->size;
    if (whence < 0 || whence > 2 || base + off < 0)
        return -EINVAL;
    f->pos = base + off;
    return f->pos;
}

static i64 sys_pipe(int *fds)
{
    if (!fds)
        return -EFAULT;
    struct pipe *p = kcalloc(1, sizeof *p);
    struct file *r = file_new(FK_PIPE_R, O_RDONLY), *w = file_new(FK_PIPE_W, O_WRONLY);
    if (!p || !r || !w) {
        kfree(p);
        kfree(r);
        kfree(w);
        return -ENOMEM;
    }
    p->readers = p->writers = 1;
    r->pipe = w->pipe = p;
    int rfd = fd_alloc(r), wfd = rfd < 0 ? -1 : fd_alloc(w);
    if (rfd < 0 || wfd < 0) {
        if (rfd >= 0)
            cur->fds[rfd] = NULL;
        file_put(r);
        file_put(w);
        return -EMFILE;
    }
    fds[0] = rfd;
    fds[1] = wfd;
    return 0;
}

static i64 sys_dup2(int oldfd, int newfd)
{
    struct file *f = fd_get(oldfd);
    if (!f || newfd < 0 || newfd >= OPEN_MAX)
        return -EBADF;
    if (oldfd == newfd)
        return newfd;
    if (cur->fds[newfd])
        file_put(cur->fds[newfd]);
    f->refs++;
    cur->fds[newfd] = f;
    return newfd;
}

static i64 sys_dup(int fd)
{
    struct file *f = fd_get(fd);
    if (!f)
        return -EBADF;
    f->refs++;
    int n = fd_alloc(f);
    if (n < 0)
        f->refs--;
    return n;
}

static i64 sys_getdents(int fd, struct dirent *out, size_t bytes)
{
    struct file *f = fd_get(fd);
    if (!f || f->kind != FK_INODE)
        return -EBADF;
    if (!ISDIR(f->ino))
        return -ENOTDIR;
    size_t max = bytes / sizeof(struct dirent), cnt = 0;
    struct inode *k = f->ino->kids;
    for (size_t i = 0;; i++) {
        const char *nm;
        struct inode *e;
        if (i == 0) {
            nm = ".";
            e = f->ino;
        } else if (i == 1) {
            nm = "..";
            e = f->ino->parent ? f->ino->parent : f->ino;
        } else {
            if (!k)
                break;
            nm = k->name;
            e = k;
            k = k->next;
        }
        if ((off_t)i < f->pos)
            continue;
        if (cnt >= max)
            break;
        struct dirent *d = &out[cnt++];
        memset(d, 0, sizeof *d);
        d->d_ino = e->ino;
        d->d_type = e->mode & S_IFMT;
        strncpy(d->d_name, nm, NAME_MAX);
        f->pos = (off_t)i + 1;
    }
    return (i64)(cnt * sizeof(struct dirent));
}

static i64 sys_rename(const char *from, const char *to)
{
    struct inode *sp, *sn, *dp, *dn;
    char sl[NAME_MAX + 1], dl[NAME_MAX + 1];
    int r;
    if (!from || !to)
        return -EFAULT;
    if ((r = namei(cur->cwd, from, &sp, sl, &sn)) || (r = namei(cur->cwd, to, &dp, dl, &dn)))
        return r;
    if (!sn)
        return -ENOENT;
    if (sn == root)
        return -EBUSY;
    if (!sl[0] || !dl[0] || !strcmp(sl, ".") || !strcmp(sl, "..") || !strcmp(dl, ".") ||
        !strcmp(dl, ".."))
        return -EINVAL;
    if (dn == sn)
        return 0;
    if (ISDIR(sn))
        for (struct inode *a = dp; a; a = a->parent)
            if (a == sn)
                return -EINVAL;
    if (dn) {
        if (ISDIR(dn)) {
            if (!ISDIR(sn))
                return -EISDIR;
            if (dn->kids || dn->refs > 0)
                return -ENOTEMPTY;
        } else if (ISDIR(sn)) {
            return -ENOTDIR;
        }
        node_remove(dn);
    }
    dir_unlink(sn);
    dir_link(dp, sn, dl);
    return 0;
}

static i64 sys_remove(const char *path, int want_dir)
{
    struct inode *par, *n;
    char leaf[NAME_MAX + 1];
    if (!path)
        return -EFAULT;
    int r = namei(cur->cwd, path, &par, leaf, &n);
    if (r)
        return r;
    if (!n)
        return -ENOENT;
    if (!leaf[0] || !strcmp(leaf, ".") || !strcmp(leaf, "..") || n == root)
        return -EINVAL;
    if (want_dir) {
        if (!ISDIR(n))
            return -ENOTDIR;
        if (n->kids)
            return -ENOTEMPTY;
        if (n->refs > 0)
            return -EBUSY;
    } else if (ISDIR(n)) {
        return -EISDIR;
    }
    node_remove(n);
    return 0;
}

static i64 sys_wait4(pid_t pid, int *status, int options)
{
    for (;;) {
        int have = 0;
        struct task *z = NULL;
        for (int i = 1; i < MAX_TASKS; i++) {
            struct task *t = &tasks[i];
            if (t->state == TS_FREE || t->ppid != cur->pid || (pid > 0 && t->pid != pid))
                continue;
            have = 1;
            if (t->state == TS_ZOMBIE) {
                z = t;
                break;
            }
        }
        if (z) {
            int rp = z->pid;
            if (status)
                *status = z->status;
            kfree(z->stack);
            z->stack = NULL;
            z->state = TS_FREE;
            return rp;
        }
        if (!have)
            return -ECHILD;
        if (options & WNOHANG)
            return 0;
        u64 fl = irq_save();
        if (sig_pending(cur)) {
            irq_restore(fl);
            return -EINTR;
        }
        sleep_on(cur);
        irq_restore(fl);
    }
}

static i64 sys_kill(pid_t pid, int sig)
{
    int found = 0;
    if (sig < 0 || sig >= NSIG)
        return -EINVAL;
    for (int i = 1; i < MAX_TASKS; i++) {
        struct task *t = &tasks[i];
        if (t->state == TS_FREE || t->state == TS_ZOMBIE)
            continue;
        if (pid > 0 ? t->pid == pid : (pid == 0 ? t->pgid == cur->pgid : t->pgid == -pid)) {
            found = 1;
            signal_send(t, sig);
        }
    }
    return found ? 0 : -ESRCH;
}

static i64 sys_nanosleep(const struct timespec *req)
{
    if (!req)
        return -EFAULT;
    u64 t = (u64)req->tv_sec * HZ + (u64)(req->tv_nsec + 9999999) / 10000000;
    u64 until = ticks + t;
    u64 fl = irq_save();
    while (ticks < until) {
        if (sig_pending(cur)) {
            irq_restore(fl);
            return -EINTR;
        }
        sleep_on(&tick_chan);
    }
    irq_restore(fl);
    return 0;
}

static i64 sys_spawn(const char *path, char *const *argv, char *const *envp,
                     const struct spawn_attr *a)
{
    struct inode *n;
    struct file *fd[3];
    int r;
    if (!path || !argv || !argv[0] || !a)
        return -EFAULT;
    if ((r = lookup(cur->cwd, path, &n)))
        return r;
    if (!ISREG(n) || !(n->mode & 0111))
        return -EACCES;
    if (!n->prog)
        return -ENOEXEC;
    for (int i = 0; i < 3; i++)
        if (!(fd[i] = fd_get(a->fd[i])))
            return -EBADF;
    char **av = dup_strv(argv), **ev = dup_strv(envp);
    if (!av || !ev) {
        kfree(av);
        kfree(ev);
        return -ENOMEM;
    }
    const char *base = argv[0];
    for (const char *s = argv[0]; *s; s++)
        if (*s == '/')
            base = s + 1;
    struct task *t = task_create(base, n->prog, av, ev, fd, cur->cwd, a->pgid, cur);
    if (!t) {
        kfree(av);
        kfree(ev);
        return -EAGAIN;
    }
    return t->pid;
}

static i64 sys_mmap(size_t len)         /* anonymous, zero-filled, freed at task exit */
{
    struct mnode *m = kcalloc(1, len + sizeof *m);
    if (!m)
        return -ENOMEM;
    m->magic = 0xA11C0DEUL;
    m->next = cur->allocs;
    if (m->next)
        m->next->prev = m;
    cur->allocs = m;
    return (i64)(m + 1);
}

static i64 sys_munmap(void *p)
{
    struct mnode *m = (struct mnode *)p - 1;
    if (!p || m->magic != 0xA11C0DEUL)
        return -EINVAL;
    if (m->prev)
        m->prev->next = m->next;
    else
        cur->allocs = m->next;
    if (m->next)
        m->next->prev = m->prev;
    m->magic = 0;
    kfree(m);
    return 0;
}

static i64 sys_ioctl(int fd, u64 req, int *arg)
{
    struct file *f = fd_get(fd);
    if (!f)
        return -EBADF;
    if (f->kind != FK_INODE || !ISCHR(f->ino) || f->ino->dev != DEV_TTY || !arg)
        return -ENOTTY;
    if (req == TIOCGPGRP)
        *arg = tty.fg;
    else if (req == TIOCSPGRP)
        tty.fg = *arg;
    else
        return -EINVAL;
    return 0;
}

static struct task *task_find(pid_t pid)
{
    if (pid == 0)
        return cur;
    for (int i = 1; i < MAX_TASKS; i++)
        if (tasks[i].state != TS_FREE && tasks[i].pid == pid)
            return &tasks[i];
    return NULL;
}

static i64 syscall_dispatch(struct regs *r)
{
    u64 a0 = r->rdi, a1 = r->rsi, a2 = r->rdx, a3 = r->r10;
    struct inode *n;
    struct file *f;
    i64 ret;
    switch (r->rax) {
    case SYS_read:
        f = fd_get((int)a0);
        ret = !f ? -EBADF : (!a1 && a2) ? -EFAULT : file_read(f, (void *)a1, a2);
        break;
    case SYS_write:
        f = fd_get((int)a0);
        ret = !f ? -EBADF : (!a1 && a2) ? -EFAULT : file_write(f, (void *)a1, a2);
        break;
    case SYS_open:
        ret = sys_open((const char *)a0, (int)a1, (u32)a2);
        break;
    case SYS_close:
        ret = sys_close((int)a0);
        break;
    case SYS_stat:
        ret = !a0 || !a1 ? -EFAULT : lookup(cur->cwd, (const char *)a0, &n);
        if (ret == 0)
            fill_stat((struct stat *)a1, n);
        break;
    case SYS_fstat:
        f = fd_get((int)a0);
        ret = !f ? -EBADF : !a1 ? -EFAULT : 0;
        if (ret == 0 && f->kind == FK_INODE) {
            fill_stat((struct stat *)a1, f->ino);
        } else if (ret == 0) {
            memset((void *)a1, 0, sizeof(struct stat));
            ((struct stat *)a1)->st_mode = 010600;
        }
        break;
    case SYS_lseek:
        ret = sys_lseek((int)a0, (off_t)a1, (int)a2);
        break;
    case SYS_mmap:
        ret = sys_mmap(a1);
        break;
    case SYS_munmap:
        ret = sys_munmap((void *)a0);
        break;
    case SYS_ioctl:
        ret = sys_ioctl((int)a0, a1, (int *)a2);
        break;
    case SYS_pipe:
        ret = sys_pipe((int *)a0);
        break;
    case SYS_dup:
        ret = sys_dup((int)a0);
        break;
    case SYS_dup2:
        ret = sys_dup2((int)a0, (int)a1);
        break;
    case SYS_nanosleep:
        ret = sys_nanosleep((const struct timespec *)a0);
        break;
    case SYS_getpid:
        ret = cur->pid;
        break;
    case SYS_getppid:
        ret = cur->ppid;
        break;
    case SYS_getpgid:
    {
        struct task *t = task_find((pid_t)a0);
        ret = t ? t->pgid : -ESRCH;
        break;
    }
    case SYS_setpgid: {
        struct task *t = task_find((pid_t)a0);
        ret = t ? 0 : -ESRCH;
        if (t)
            t->pgid = a1 ? (int)a1 : t->pid;
        break;
    }
    case SYS_signal:
        if (a0 == 0 || a0 >= NSIG || a0 == SIGKILL || (a1 != SIG_DFL && a1 != SIG_IGN)) {
            ret = -EINVAL;
            break;
        }
        ret = (cur->sigign >> a0) & 1;
        if (a1 == SIG_IGN) {
            cur->sigign |= 1u << a0;
            cur->sigpend &= ~(1u << a0);
        } else {
            cur->sigign &= ~(1u << a0);
        }
        break;
    case SYS_exit:
        task_exit((int)((a0 & 0xFF) << 8));
    case SYS_wait4:
        ret = sys_wait4((pid_t)a0, (int *)a1, (int)a2);
        break;
    case SYS_kill:
        ret = sys_kill((pid_t)a0, (int)a1);
        break;
    case SYS_uname: {
        struct utsname *u = (struct utsname *)a0;
        ret = u ? 0 : -EFAULT;
        if (u) {
            strcpy(u->sysname, "AdicoDOS");
            strcpy(u->nodename, "adico");
            strcpy(u->release, "1.0");
            strcpy(u->version, "Q-DOS-sized POSIX toy");
            strcpy(u->machine, "x86_64");
        }
        break;
    }
    case SYS_getdents:
        ret = sys_getdents((int)a0, (struct dirent *)a1, a2);
        break;
    case SYS_getcwd:
        ret = a0 ? cwd_path(cur->cwd, (char *)a0, a1) : -EFAULT;
        break;
    case SYS_chdir:
        ret = !a0 ? -EFAULT : lookup(cur->cwd, (const char *)a0, &n);
        if (ret == 0 && !ISDIR(n))
            ret = -ENOTDIR;
        if (ret == 0) {
            n->refs++;
            iput(cur->cwd);
            cur->cwd = n;
        }
        break;
    case SYS_rename:
        ret = sys_rename((const char *)a0, (const char *)a1);
        break;
    case SYS_mkdir:
        ret = !a0 ? -EFAULT : vfs_create(cur->cwd, (const char *)a0, S_IFDIR | (a1 & 0777 & ~022u), NULL);
        break;
    case SYS_rmdir:
        ret = sys_remove((const char *)a0, 1);
        break;
    case SYS_unlink:
        ret = sys_remove((const char *)a0, 0);
        break;
    case SYS_chmod:
        ret = !a0 ? -EFAULT : lookup(cur->cwd, (const char *)a0, &n);
        if (ret == 0)
            n->mode = (n->mode & S_IFMT) | (a1 & 0777);
        break;
    case SYS_sysinfo: {
        struct sysinfo *si = (struct sysinfo *)a0;
        ret = si ? 0 : -EFAULT;
        if (si) {
            si->uptime_ticks = ticks;
            si->mem_total = (u64)(heap_hi - heap_lo);
            si->mem_free = heap_free_bytes();
            si->nprocs = 0;
            for (int i = 1; i < MAX_TASKS; i++)
                if (tasks[i].state != TS_FREE)
                    si->nprocs++;
            si->fs_nodes = fs_nodes;
            si->fs_bytes = fs_bytes;
            si->disk_sectors = disk_sectors;
        }
        break;
    }
    case SYS_procinfo: {
        struct pinfo *pi = (struct pinfo *)a0;
        int cnt = 0;
        ret = pi ? 0 : -EFAULT;
        for (int i = 1; pi && i < MAX_TASKS && cnt < (int)a1; i++) {
            if (tasks[i].state == TS_FREE)
                continue;
            pi[cnt].pid = tasks[i].pid;
            pi[cnt].ppid = tasks[i].ppid;
            pi[cnt].pgid = tasks[i].pgid;
            pi[cnt].state = tasks[i].state;
            strncpy(pi[cnt].name, tasks[i].name, 15);
            pi[cnt].name[15] = 0;
            cnt++;
        }
        if (pi)
            ret = cnt;
        break;
    }
    case SYS_sync:
        ret = disk_sectors ? fs_save() : -ENODEV;
        break;
    case SYS_reboot:
        system_off(a0 == 2, a0 == 2 ? "reboot requested" : "power off requested");
    case SYS_time:
        ret = time_now();
        if (a0)
            *(time_t *)a0 = ret;
        break;
    case SYS_spawn:
        ret = sys_spawn((const char *)a0, (char *const *)a1, (char *const *)a2,
                        (const struct spawn_attr *)a3);
        break;
    default:
        ret = -ENOSYS;
    }
    signal_check();                     /* deliver terminating signals on syscall exit */
    return ret;
}

/* =========================================================================
 * 12. DISK SNAPSHOT: "sync" saves everything outside /dev and /bin to sector 0..
 * ========================================================================= */
struct dhdr {
    char magic[8];
    u32 count, bytes, sum, rsvd;
};
struct drec {
    u32 mode, plen;
    u64 dlen;
};
struct sbuf {
    u8 *p;
    size_t len, cap;
};

static int sb_put(struct sbuf *b, const void *p, size_t n)
{
    if (b->len + n > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 4096;
        while (nc < b->len + n)
            nc *= 2;
        u8 *q = krealloc(b->p, nc);
        if (!q)
            return -ENOMEM;
        b->p = q;
        b->cap = nc;
    }
    memcpy(b->p + b->len, p, n);
    b->len += n;
    return 0;
}

static u32 checksum(const u8 *p, size_t n)
{
    u32 s = 0;
    for (size_t i = 0; i < n; i++)
        s = ((s << 5) | (s >> 27)) ^ p[i];
    return s;
}

static int ser_dir(struct sbuf *b, struct inode *d, char *path, size_t plen, u32 *count)
{
    for (struct inode *k = d->kids; k; k = k->next) {
        size_t l = strlen(k->name);
        if ((d == root && (!strcmp(k->name, "dev") || !strcmp(k->name, "bin"))) || ISCHR(k) ||
            k->prog || plen + 1 + l >= PATH_MAX)
            continue;
        path[plen] = '/';
        memcpy(path + plen + 1, k->name, l + 1);
        struct drec rc = { k->mode, (u32)(plen + 2 + l), ISREG(k) ? k->size : 0 };
        if (sb_put(b, &rc, sizeof rc) || sb_put(b, path, rc.plen) ||
            (rc.dlen && sb_put(b, k->data, rc.dlen)))
            return -ENOMEM;
        (*count)++;
        if (ISDIR(k) && ser_dir(b, k, path, plen + 1 + l, count))
            return -ENOMEM;
        path[plen] = 0;
    }
    return 0;
}

static int fs_save(void)
{
    struct sbuf b = { 0, 0, 0 };
    struct dhdr h;
    char path[PATH_MAX] = "";
    u32 count = 0;
    memset(&h, 0, sizeof h);
    if (sb_put(&b, &h, sizeof h) || ser_dir(&b, root, path, 0, &count)) {
        kfree(b.p);
        return -ENOMEM;
    }
    size_t used = b.len, sectors = (used + 511) / 512;
    if (sectors > disk_sectors) {
        kfree(b.p);
        return -ENOSPC;
    }
    u8 zero[512] = { 0 };
    if (sb_put(&b, zero, sectors * 512 - used)) {
        kfree(b.p);
        return -ENOMEM;
    }
    struct dhdr *hp = (struct dhdr *)b.p;
    memcpy(hp->magic, "ADICODOS", 8);
    hp->count = count;
    hp->bytes = (u32)used;
    hp->sum = checksum(b.p + sizeof *hp, used - sizeof *hp);
    int r = 0;
    for (size_t i = 0; i < sectors && !r; i++)
        r = ata_rw((u32)i, (u16 *)(b.p + i * 512), 1);
    kfree(b.p);
    return r;
}

static void restore_node(const char *path, u32 mode, const u8 *data, size_t dlen)
{
    struct inode *par, *n;
    char leaf[NAME_MAX + 1];
    if (namei(root, path, &par, leaf, &n) || !leaf[0])
        return;
    if (!n) {
        n = inode_new(mode);
        if (!n)
            return;
        dir_link(par, n, leaf);
    } else if (ISDIR(n) != ((mode & S_IFMT) == S_IFDIR)) {
        return;
    }
    n->mode = mode;
    if (ISREG(n)) {
        node_truncate(n);
        if (dlen)
            node_write(n, 0, data, dlen);
    }
}

static void fs_load(void)
{
    struct dhdr h;
    u8 sec[512];
    if (!disk_sectors || ata_rw(0, (u16 *)sec, 0))
        return;
    memcpy(&h, sec, sizeof h);
    if (memcmp(h.magic, "ADICODOS", 8)) {
        kprintf("disk: no Adico DOS snapshot found (blank disk)\n");
        return;
    }
    size_t sectors = (h.bytes + 511) / 512;
    if (h.bytes < sizeof h || h.bytes > (32u << 20) || sectors > disk_sectors)
        return;
    u8 *buf = kmalloc(sectors * 512);
    if (!buf)
        return;
    for (size_t i = 0; i < sectors; i++)
        if (ata_rw((u32)i, (u16 *)(buf + i * 512), 0)) {
            kfree(buf);
            return;
        }
    if (checksum(buf + sizeof h, h.bytes - sizeof h) != h.sum) {
        kprintf("disk: snapshot checksum mismatch, ignoring\n");
        kfree(buf);
        return;
    }
    const u8 *p = buf + sizeof h, *end = buf + h.bytes;
    while (p + sizeof(struct drec) <= end) {
        struct drec rc;
        memcpy(&rc, p, sizeof rc);
        p += sizeof rc;
        if (rc.plen == 0 || p + rc.plen + rc.dlen > end)
            break;
        restore_node((const char *)p, rc.mode, p + rc.plen, rc.dlen);
        p += rc.plen + rc.dlen;
    }
    kprintf("disk: restored %u entries from snapshot\n", h.count);
    kfree(buf);
}

/* ---- initial file system image ---- */
static void fs_text(const char *path, const char *text)
{
    struct inode *n;
    if (!vfs_create(root, path, S_IFREG | 0644, &n))
        node_write(n, 0, text, strlen(text));
}

static void fs_init(void)
{
    static const char *dirs[] = { "/bin", "/dev", "/etc", "/home", "/tmp" };
    static const struct { const char *name; int dev; } devs[] = {
        { "/dev/console", DEV_TTY }, { "/dev/tty", DEV_TTY }, { "/dev/null", DEV_NULL },
        { "/dev/zero", DEV_ZERO }, { "/dev/urandom", DEV_RANDOM }
    };
    struct inode *n;
    root = inode_new(S_IFDIR | 0755);
    for (size_t i = 0; i < sizeof dirs / sizeof *dirs; i++)
        vfs_create(root, dirs[i], S_IFDIR | 0755, NULL);
    for (size_t i = 0; i < sizeof devs / sizeof *devs; i++)
        if (!vfs_create(root, devs[i].name, S_IFCHR | 0666, &n))
            n->dev = devs[i].dev;
    for (const struct prog *p = posix_progs; p->name; p++) {
        char path[PATH_MAX];
        snprintf(path, sizeof path, "/bin/%s", p->name);
        if (!vfs_create(root, path, S_IFREG | 0755, &n))
            n->prog = p->main;
    }
    fs_text("/etc/motd",
            "Adico DOS 1.0 (x86_64) - a Q-DOS sized, POSIX-flavored toy operating system.\n"
            "Type 'help' for the shell built-ins and 'ls /bin' for the utilities.\n"
            "Files live in RAM; run 'sync' to save them to the disk image.\n");
    fs_text("/etc/hostname", "adico\n");
    fs_text("/etc/profile",
            "# /etc/profile - executed by the init shell at startup\n"
            "export PATH=/bin\n"
            "export HOME=/home\n"
            "export USER=root\n"
            "export HOSTNAME=adico\n"
            "cd $HOME\n");
    fs_text("/home/hello.sh",
            "# Sample script. Run it with: sh /home/hello.sh world\n"
            "echo \"Hello from $0, first argument: $1\"\n"
            "ls /bin | wc -l\n");
}

/* =========================================================================
 * 13. TRAPS: IDT, PIC, exceptions, IRQs
 * ========================================================================= */
struct idt_entry {
    u16 lo, sel;
    u8 ist, attr;
    u16 mid;
    u32 hi, zero;
} PACKED;
struct idtr {
    u16 limit;
    u64 base;
} PACKED;
static struct idt_entry idt[256];

static void idt_set(int v, u64 h, u8 attr)
{
    idt[v].lo = (u16)(h & 0xFFFF);
    idt[v].sel = 0x08;
    idt[v].ist = 0;
    idt[v].attr = attr;
    idt[v].mid = (u16)((h >> 16) & 0xFFFF);
    idt[v].hi = (u32)(h >> 32);
    idt[v].zero = 0;
}

static void pic_init(void)
{
    port_outb(0x20, 0x11);
    port_outb(0xA0, 0x11);
    port_outb(0x21, 0x20);              /* master vectors 0x20-0x27 */
    port_outb(0xA1, 0x28);              /* slave vectors 0x28-0x2F */
    port_outb(0x21, 0x04);
    port_outb(0xA1, 0x02);
    port_outb(0x21, 0x01);
    port_outb(0xA1, 0x01);
    port_outb(0x21, 0xE8);              /* unmask IRQ0 timer, IRQ1 keyboard, IRQ2 cascade, IRQ4 COM1 */
    port_outb(0xA1, 0xFF);
}

static void idt_init(void)
{
    static struct idtr ptr;
    for (int v = 0; v < 48; v++)
        idt_set(v, isr_stub_table[v], 0x8E);
    idt_set(0x80, (u64)isr_stub_128, 0x8F);     /* trap gate: syscalls keep IRQs enabled */
    ptr.limit = sizeof idt - 1;
    ptr.base = (u64)idt;
    idt_load(&ptr);
}

static NORETURN void system_off(int reboot, const char *why)
{
    cpu_cli();
    kprintf("\nadico: %s\n", why);
    if (disk_sectors)
        kprintf("sync: %s\n", fs_save() ? "FAILED" : "file system saved");
    kprintf(reboot ? "Rebooting...\n" : "System halted. It is now safe to power off.\n");
    if (reboot)
        port_outb(0x64, 0xFE);
    port_outw(0x604, 0x2000);           /* QEMU / Bochs ACPI power off */
    port_outw(0xB004, 0x2000);
    for (;;)
        cpu_halt();
}

static void exception(struct regs *r)
{
    static const char *const names[] = {
        "Divide error", "Debug", "NMI", "Breakpoint", "Overflow", "Bound range",
        "Invalid opcode", "Device not available", "Double fault", "Coprocessor overrun",
        "Invalid TSS", "Segment not present", "Stack fault", "General protection",
        "Page fault", "Reserved", "x87 error", "Alignment check", "Machine check", "SIMD error"
    };
    const char *nm = r->vec < 20 ? names[r->vec] : "Exception";
    if (cur->pid > 0 && r->vec != 8) {  /* fault inside a program: kill just that task */
        kprintf("\n%s (vector %lu, error 0x%lx) at rip=%p, address=%p: terminating pid %d\n", nm,
                r->vec, r->err, (void *)r->rip, (void *)cpu_cr2(), cur->pid);
        task_exit(r->vec == 0 ? SIGFPE : r->vec == 6 ? SIGILL : SIGSEGV);
    }
    kprintf("\n*** KERNEL PANIC: %s (vector %lu, error 0x%lx)\n", nm, r->vec, r->err);
    kprintf("rip=%p rsp=%p rflags=0x%lx cr2=%p\n", (void *)r->rip, (void *)r->rsp, r->rflags,
            (void *)cpu_cr2());
    kprintf("rax=%p rbx=%p rcx=%p rdx=%p\nrsi=%p rdi=%p rbp=%p\n", (void *)r->rax, (void *)r->rbx,
            (void *)r->rcx, (void *)r->rdx, (void *)r->rsi, (void *)r->rdi, (void *)r->rbp);
    cpu_cli();
    for (;;)
        cpu_halt();
}

static void irq_handler(int irq)
{
    switch (irq) {
    case 0:
        ticks++;
        wakeup(&tick_chan);
        serial_irq();                   /* poll in case a receive interrupt was missed */
        break;
    case 1:
        kbd_irq();
        break;
    case 4:
        serial_irq();
        break;
    default:
        break;
    }
    if (irq >= 8)
        port_outb(0xA0, 0x20);
    port_outb(0x20, 0x20);
}

void isr_dispatch(struct regs *r)
{
    if (r->vec == 0x80)
        r->rax = (u64)syscall_dispatch(r);
    else if (r->vec >= 32)
        irq_handler((int)r->vec - 32);
    else
        exception(r);
}

/* =========================================================================
 * 14. KERNEL ENTRY
 * ========================================================================= */
void kmain(u32 magic, u32 mbi_addr)
{
    const u32 *mbi = (const u32 *)(u64)mbi_addr;
    u64 mem_top = 0x100000 + 63UL * 1024 * 1024;        /* default: 64 MiB */

    serial_init();
    vga_clear();
    kprintf("\033[1;36mAdico DOS 1.0\033[0m (x86_64) booting...\n");
    if (magic == 0x2BADB002 && (mbi[0] & 1))
        mem_top = 0x100000 + (u64)mbi[2] * 1024;        /* mem_upper is in KiB above 1 MiB */
    if (mem_top > 0x40000000UL)
        mem_top = 0x40000000UL;
    u64 heap_start = ((u64)__kernel_end + 4095) & ~4095UL;
    if (mem_top < heap_start + (4UL << 20))
        mem_top = heap_start + (4UL << 20);
    heap_init(heap_start, mem_top);
    kprintf("memory: %lu KiB heap, kernel ends at %p\n", (mem_top - heap_start) / 1024,
            (void *)__kernel_end);

    idt_init();
    pic_init();
    pit_init();
    rtc_init();
    ata_init();
    if (disk_sectors)
        kprintf("disk: ATA drive, %u sectors (%u KiB)\n", disk_sectors, disk_sectors / 2);
    else
        kprintf("disk: none (changes will not persist)\n");
    fs_init();
    fs_load();

    tasks[0].state = TS_SLEEP;                          /* boot context only ever idles */
    struct file *con = file_new(FK_INODE, O_RDWR);
    struct inode *cn;
    if (!con || lookup(root, "/dev/console", &cn))
        for (;;)
            cpu_halt();
    con->ino = cn;
    cn->refs++;
    struct file *fds[3] = { con, con, con };
    static char *init_argv[] = { "init", NULL };
    static char *init_envp[] = { NULL };
    struct task *init = task_create("init", posix_init_main, dup_strv(init_argv),
                                    dup_strv(init_envp), fds, root, -1, NULL);
    file_put(con);
    if (!init)
        for (;;)
            cpu_halt();
    kprintf("starting init (pid %d)\n\n", init->pid);
    cpu_cli();
    schedule();                                         /* never returns to the boot context */
    for (;;)
        cpu_halt();
}