/*
 * adico_posix.c -- Adico DOS POSIX compatibility layer, shell and utilities
 *
 *   1. shared ABI            4. POSIX shell (sh)
 *   2. system call stubs     5. utilities installed in /bin
 *   3. libc subset           6. program table and init entry point
 *
 * This file talks to the kernel only through "int 0x80". The tiny string and
 * printf core (strlen, strcmp, vsnprintf, ...) is shared with the kernel at
 * link time. Programs keep no mutable globals except errno: they run as
 * cooperative tasks in one address space, so per-program state lives on
 * each program's own stack.
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

void *memcpy(void *d, const void *s, size_t n);
void *memset(void *d, int c, size_t n);
void *memmove(void *d, const void *s, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);
char *strchr(const char *s, int c);
char *strcpy(char *d, const char *s);
char *strncpy(char *d, const char *s, size_t n);
int vsnprintf(char *buf, size_t n, const char *fmt, va_list ap);
int snprintf(char *buf, size_t n, const char *fmt, ...);

#define NORETURN __attribute__((noreturn))
#define PROG(name) static int name(int argc, char **argv, char **envp)

/* =========================================================================
 * 2. SYSTEM CALL STUBS
 * ========================================================================= */
int errno;

static long sc(long n, long a, long b, long c, long d, long e, long f)
{
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long ret;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "memory", "cc");
    return ret;
}

static long sysret(long r)
{
    if (r < 0) {
        errno = (int)-r;
        return -1;
    }
    return r;
}

#define SYS(n, a, b, c) sysret(sc(n, (long)(a), (long)(b), (long)(c), 0, 0, 0))

ssize_t read(int fd, void *buf, size_t n) { return SYS(SYS_read, fd, buf, n); }
ssize_t write(int fd, const void *buf, size_t n) { return SYS(SYS_write, fd, buf, n); }
int close(int fd) { return (int)SYS(SYS_close, fd, 0, 0); }
off_t lseek(int fd, off_t off, int wh) { return SYS(SYS_lseek, fd, off, wh); }
int stat(const char *p, struct stat *st) { return (int)SYS(SYS_stat, p, st, 0); }
int pipe(int fds[2]) { return (int)SYS(SYS_pipe, fds, 0, 0); }
int dup2(int a, int b) { return (int)SYS(SYS_dup2, a, b, 0); }
pid_t getpid(void) { return (pid_t)SYS(SYS_getpid, 0, 0, 0); }
pid_t getpgid(pid_t p) { return (pid_t)SYS(SYS_getpgid, p, 0, 0); }
pid_t waitpid(pid_t p, int *st, int opt) { return (pid_t)SYS(SYS_wait4, p, st, opt); }
int kill(pid_t p, int sig) { return (int)SYS(SYS_kill, p, sig, 0); }
int chdir(const char *p) { return (int)SYS(SYS_chdir, p, 0, 0); }
int mkdir(const char *p, mode_t m) { return (int)SYS(SYS_mkdir, p, m, 0); }
int rmdir(const char *p) { return (int)SYS(SYS_rmdir, p, 0, 0); }
int unlink(const char *p) { return (int)SYS(SYS_unlink, p, 0, 0); }
int rename(const char *a, const char *b) { return (int)SYS(SYS_rename, a, b, 0); }
int chmod(const char *p, mode_t m) { return (int)SYS(SYS_chmod, p, m, 0); }
int uname(struct utsname *u) { return (int)SYS(SYS_uname, u, 0, 0); }
int ioctl(int fd, unsigned long rq, void *arg) { return (int)SYS(SYS_ioctl, fd, rq, arg); }
int nanosleep(const struct timespec *t) { return (int)SYS(SYS_nanosleep, t, 0, 0); }
time_t time(void) { return SYS(SYS_time, 0, 0, 0); }
int sysinfo(struct sysinfo *si) { return (int)SYS(SYS_sysinfo, si, 0, 0); }
int procinfo(struct pinfo *pi, int max) { return (int)SYS(SYS_procinfo, pi, max, 0); }
int sync(void) { return (int)SYS(SYS_sync, 0, 0, 0); }
int reboot_adico(int cmd) { return (int)SYS(SYS_reboot, cmd, 0, 0); }
int sig_ignore(int sig, int on) { return (int)SYS(SYS_signal, sig, on ? SIG_IGN : SIG_DFL, 0); }
pid_t spawn(const char *path, char *const argv[], char *const envp[], const struct spawn_attr *a)
{
    return (pid_t)sysret(sc(SYS_spawn, (long)path, (long)argv, (long)envp, (long)a, 0, 0));
}
char *getcwd(char *buf, size_t n)
{
    return SYS(SYS_getcwd, buf, n, 0) < 0 ? NULL : buf;
}
int isatty(int fd)
{
    int pg;
    return ioctl(fd, TIOCGPGRP, &pg) == 0;
}
int open(const char *path, int flags, ...)
{
    int mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    return (int)SYS(SYS_open, path, flags, mode);
}
NORETURN void exit(int code)
{
    sc(SYS_exit, code, 0, 0, 0, 0, 0);
    for (;;)
        ;
}

/* =========================================================================
 * 3. LIBC SUBSET
 * ========================================================================= */
int isdigit(int c) { return c >= '0' && c <= '9'; }
int isalpha(int c) { return (c | 32) >= 'a' && (c | 32) <= 'z'; }
int isspace(int c) { return c == ' ' || (c >= 9 && c <= 13); }
int tolower(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }

void *malloc(size_t n)
{
    u64 *p = (u64 *)sc(SYS_mmap, 0, (long)n + 16, 3, 0x22, -1, 0);
    if ((long)p < 0) {
        errno = ENOMEM;
        return NULL;
    }
    p[0] = n;
    return p + 2;
}

void free(void *p)
{
    if (p)
        sc(SYS_munmap, (long)((u64 *)p - 2), 0, 0, 0, 0, 0);
}

void *realloc(void *p, size_t n)
{
    if (!p)
        return malloc(n);
    size_t old = ((u64 *)p)[-2];
    if (n <= old)
        return p;
    void *q = malloc(n);
    if (q) {
        memcpy(q, p, old);
        free(p);
    }
    return q;
}

void *calloc(size_t a, size_t b)
{
    return malloc(a * b);               /* mmap blocks are always zero-filled */
}

char *strrchr(const char *s, int c)
{
    const char *r = NULL;
    for (;; s++) {
        if (*s == (char)c)
            r = s;
        if (!*s)
            return (char *)r;
    }
}

char *strstr(const char *h, const char *n)
{
    size_t l = strlen(n);
    for (; *h; h++)
        if (!strncmp(h, n, l))
            return (char *)h;
    return l ? NULL : (char *)h;
}

char *strdup(const char *s)
{
    size_t l = strlen(s) + 1;
    char *p = malloc(l);
    if (p)
        memcpy(p, s, l);
    return p;
}

char *strndup(const char *s, size_t n)
{
    char *p = malloc(n + 1);
    if (p) {
        memcpy(p, s, n);
        p[n] = 0;
    }
    return p;
}

long strtol(const char *s, char **end, int base)
{
    long v = 0;
    int neg = 0;
    while (isspace(*s))
        s++;
    if (*s == '-' || *s == '+')
        neg = *s++ == '-';
    if ((base == 0 || base == 16) && s[0] == '0' && (s[1] | 32) == 'x') {
        s += 2;
        base = 16;
    } else if (base == 0) {
        base = s[0] == '0' ? 8 : 10;
    }
    for (;; s++) {
        int d = isdigit(*s) ? *s - '0' : isalpha(*s) ? (*s | 32) - 'a' + 10 : 99;
        if (d >= base)
            break;
        v = v * base + d;
    }
    if (end)
        *end = (char *)s;
    return neg ? -v : v;
}

/* Shell sort: in place, no recursion, no global state. */
void qsort(void *base, size_t n, size_t sz, int (*cmp)(const void *, const void *))
{
    char *a = base, tmp[64];
    for (size_t gap = n / 2; gap; gap /= 2) {
        for (size_t i = gap; i < n; i++) {
            size_t j = i;
            memcpy(tmp, a + i * sz, sz);
            while (j >= gap && cmp(a + (j - gap) * sz, tmp) > 0) {
                memcpy(a + j * sz, a + (j - gap) * sz, sz);
                j -= gap;
            }
            memcpy(a + j * sz, tmp, sz);
        }
    }
}

const char *strerror(int e)
{
    switch (e) {
    case EPERM: return "Operation not permitted";
    case ENOENT: return "No such file or directory";
    case ESRCH: return "No such process";
    case EINTR: return "Interrupted system call";
    case EIO: return "Input/output error";
    case ENOEXEC: return "Exec format error";
    case EBADF: return "Bad file descriptor";
    case ECHILD: return "No child processes";
    case EAGAIN: return "Resource temporarily unavailable";
    case ENOMEM: return "Cannot allocate memory";
    case EACCES: return "Permission denied";
    case EFAULT: return "Bad address";
    case EBUSY: return "Device or resource busy";
    case EEXIST: return "File exists";
    case ENODEV: return "No such device";
    case ENOTDIR: return "Not a directory";
    case EISDIR: return "Is a directory";
    case EINVAL: return "Invalid argument";
    case EMFILE: return "Too many open files";
    case ENOTTY: return "Inappropriate ioctl for device";
    case EFBIG: return "File too large";
    case ENOSPC: return "No space left on device";
    case ESPIPE: return "Illegal seek";
    case EPIPE: return "Broken pipe";
    case ERANGE: return "Result too large";
    case ENAMETOOLONG: return "File name too long";
    case ENOSYS: return "Function not implemented";
    case ENOTEMPTY: return "Directory not empty";
    default: return "Unknown error";
    }
}

int write_all(int fd, const void *buf, size_t n)
{
    const char *p = buf;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0)
            return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

int vdprintf(int fd, const char *fmt, va_list ap)
{
    char buf[512];
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    if (n > (int)sizeof buf - 1)
        n = sizeof buf - 1;
    write_all(fd, buf, (size_t)n);
    return n;
}

int dprintf(int fd, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vdprintf(fd, fmt, ap);
    va_end(ap);
    return n;
}

int printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vdprintf(1, fmt, ap);
    va_end(ap);
    return n;
}

void perror(const char *s)
{
    dprintf(2, "%s: %s\n", s, strerror(errno));
}

/* ---- helpers used by the shell and the utilities ---- */
static const char *base_name(const char *p)
{
    const char *r = strrchr(p, '/');
    return r ? r + 1 : p;
}

static int is_dir(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0 && (st.st_mode & S_IFMT) == S_IFDIR;
}

static void join_path(char *out, size_t n, const char *dir, const char *name)
{
    size_t l = strlen(dir);
    snprintf(out, n, "%s%s%s", dir, (l && dir[l - 1] == '/') ? "" : "/", name);
}

/* Reads a directory into a malloc'd array (sorted, including "." and ".."). */
static int dir_load(const char *path, struct dirent **out, int *count)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY);
    if (fd < 0)
        return -1;
    size_t cap = 16, n = 0;
    struct dirent *v = malloc(cap * sizeof *v);
    while (v) {
        if (n == cap) {
            struct dirent *nv = realloc(v, cap * 2 * sizeof *v);
            if (!nv)
                break;
            v = nv;
            cap *= 2;
        }
        long r = SYS(SYS_getdents, fd, v + n, (cap - n) * sizeof *v);
        if (r <= 0) {
            close(fd);
            if (r < 0) {
                free(v);
                return -1;
            }
            *out = v;
            *count = (int)n;
            return 0;
        }
        n += (size_t)r / sizeof *v;
    }
    close(fd);
    free(v);
    errno = ENOMEM;
    return -1;
}

static char *slurp(int fd, size_t *len)  /* whole stream into one malloc'd, NUL-terminated buffer */
{
    size_t cap = 1024, n = 0;
    char *b = malloc(cap);
    while (b) {
        if (n + 1 >= cap) {
            char *nb = realloc(b, cap * 2);
            if (!nb)
                break;
            b = nb;
            cap *= 2;
        }
        ssize_t r = read(fd, b + n, cap - n - 1);
        if (r <= 0) {
            if (r < 0) {
                free(b);
                return NULL;
            }
            b[n] = 0;
            *len = n;
            return b;
        }
        n += (size_t)r;
    }
    free(b);
    errno = ENOMEM;
    return NULL;
}

struct lr {                             /* buffered line reader */
    int fd, eof;
    char *buf;
    size_t cap, len, pos;
};

static char *lr_next(struct lr *r)
{
    for (;;) {
        for (size_t i = r->pos; i < r->len; i++) {
            if (r->buf[i] == '\n') {
                char *l = r->buf + r->pos;
                r->buf[i] = 0;
                r->pos = i + 1;
                return l;
            }
        }
        if (r->eof) {
            if (r->pos < r->len) {
                char *l = r->buf + r->pos;
                r->buf[r->len] = 0;
                r->pos = r->len;
                return l;
            }
            return NULL;
        }
        if (r->pos) {
            memmove(r->buf, r->buf + r->pos, r->len - r->pos);
            r->len -= r->pos;
            r->pos = 0;
        }
        if (r->len + 1 >= r->cap) {
            size_t nc = r->cap ? r->cap * 2 : 1024;
            char *nb = realloc(r->buf, nc);
            if (!nb) {
                r->eof = 1;
                continue;
            }
            r->buf = nb;
            r->cap = nc;
        }
        ssize_t n = read(r->fd, r->buf + r->len, r->cap - r->len - 1);
        if (n <= 0)
            r->eof = 1;
        else
            r->len += (size_t)n;
    }
}

struct gopt {                           /* POSIX-style getopt with per-call state */
    int ind, pos;
    char *arg;
};

static int gopt_next(struct gopt *g, int argc, char **argv, const char *spec)
{
    if (g->pos == 0) {
        if (g->ind >= argc || argv[g->ind][0] != '-' || !argv[g->ind][1])
            return -1;
        if (!strcmp(argv[g->ind], "--")) {
            g->ind++;
            return -1;
        }
        g->pos = 1;
    }
    char c = argv[g->ind][g->pos++];
    const char *o = strchr(spec, c);
    if (!o || c == ':') {
        dprintf(2, "%s: invalid option -- '%c'\n", argv[0], c);
        if (!argv[g->ind][g->pos]) {
            g->ind++;
            g->pos = 0;
        }
        return '?';
    }
    if (o[1] == ':') {
        if (argv[g->ind][g->pos]) {
            g->arg = &argv[g->ind][g->pos];
        } else if (g->ind + 1 < argc) {
            g->arg = argv[++g->ind];
        } else {
            dprintf(2, "%s: option requires an argument -- '%c'\n", argv[0], c);
            g->ind++;
            g->pos = 0;
            return '?';
        }
        g->ind++;
        g->pos = 0;
        return c;
    }
    if (!argv[g->ind][g->pos]) {
        g->ind++;
        g->pos = 0;
    }
    return c;
}

struct tmv {
    int year, mon, day, hour, min, sec, wday;
};

static void gmtime_adico(time_t t, struct tmv *tm)
{
    long days = t / 86400, rem = t % 86400;
    if (rem < 0) {
        rem += 86400;
        days--;
    }
    tm->hour = (int)(rem / 3600);
    tm->min = (int)(rem % 3600 / 60);
    tm->sec = (int)(rem % 60);
    tm->wday = (int)((days + 4) % 7 + 7) % 7;
    days += 719468;
    long era = (days >= 0 ? days : days - 146096) / 146097;
    long doe = days - era * 146097;
    long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    long mp = (5 * doy + 2) / 153;
    tm->day = (int)(doy - (153 * mp + 2) / 5 + 1);
    tm->mon = (int)(mp < 10 ? mp + 3 : mp - 9);
    tm->year = (int)(yoe + era * 400 + (tm->mon <= 2));
}

static const char *const MONTHS[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
static const char *const WDAYS[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

/* =========================================================================
 * 4. POSIX SHELL
 *    Supports: pipelines, && || ; &, redirections (< > >> 2> 2>> 2>&1),
 *    quoting, $VAR ${VAR} $? $$ $# $0-$9, ~ and * ? globbing, PATH search,
 *    scripts (sh file, sh -c, '.'), job control with process groups and ^C.
 *    Not supported: compound commands (if/for/while), functions, $(...).
 * ========================================================================= */
#define MAXVARS 48
#define MAXTOK 256
#define MAXPIPE 16

struct var {
    char *name, *val;
    int exp;
};

struct shell {
    struct var vars[MAXVARS];
    int nvars, status, interactive, exiting;
    char *args[10];
    int nargs;
    pid_t bg[16];
    int nbg;
};

struct av {                             /* growable NULL-terminated argument vector */
    char **v;
    int n, cap;
};

struct str {                            /* word under construction; m[i]=1 means quoted */
    char *s, *m;
    size_t n, cap;
};

static void av_add(struct av *a, char *s)
{
    if (a->n + 2 > a->cap) {
        a->cap = a->cap ? a->cap * 2 : 8;
        a->v = realloc(a->v, (size_t)a->cap * sizeof(char *));
    }
    a->v[a->n++] = s;
    a->v[a->n] = NULL;
}

static void av_free(struct av *a)
{
    for (int i = 0; i < a->n; i++)
        free(a->v[i]);
    free(a->v);
    a->v = NULL;
    a->n = a->cap = 0;
}

static void str_put(struct str *x, char c, char m)
{
    if (x->n + 2 > x->cap) {
        x->cap = x->cap ? x->cap * 2 : 32;
        x->s = realloc(x->s, x->cap);
        x->m = realloc(x->m, x->cap);
    }
    x->s[x->n] = c;
    x->m[x->n] = m;
    x->n++;
    x->s[x->n] = 0;
    x->m[x->n] = 0;
}

/* ---- variables ---- */
static struct var *var_find(struct shell *sh, const char *name, size_t len)
{
    for (int i = 0; i < sh->nvars; i++)
        if (strlen(sh->vars[i].name) == len && !strncmp(sh->vars[i].name, name, len))
            return &sh->vars[i];
    return NULL;
}

static const char *var_get(struct shell *sh, const char *name)
{
    struct var *v = var_find(sh, name, strlen(name));
    return v ? v->val : NULL;
}

static void var_set(struct shell *sh, const char *name, const char *val, int exp)
{
    struct var *v = var_find(sh, name, strlen(name));
    if (!v) {
        if (sh->nvars >= MAXVARS)
            return;
        v = &sh->vars[sh->nvars++];
        v->name = strdup(name);
        v->val = NULL;
        v->exp = 0;
    }
    free(v->val);
    v->val = strdup(val);
    if (exp >= 0)
        v->exp = exp;
}

static void var_unset(struct shell *sh, const char *name)
{
    struct var *v = var_find(sh, name, strlen(name));
    if (!v)
        return;
    free(v->name);
    free(v->val);
    *v = sh->vars[--sh->nvars];
}

static char **build_env(struct shell *sh)
{
    char **e = malloc((size_t)(sh->nvars + 1) * sizeof(char *));
    int n = 0;
    for (int i = 0; e && i < sh->nvars; i++) {
        if (!sh->vars[i].exp)
            continue;
        size_t l = strlen(sh->vars[i].name) + strlen(sh->vars[i].val) + 2;
        e[n] = malloc(l);
        snprintf(e[n++], l, "%s=%s", sh->vars[i].name, sh->vars[i].val);
    }
    if (e)
        e[n] = NULL;
    return e;
}

static void free_vec(char **v)
{
    for (int i = 0; v && v[i]; i++)
        free(v[i]);
    free(v);
}

/* ---- word expansion: variables, quotes, tilde, globbing ---- */
static const char *expand_dollar(struct shell *sh, const char *p, struct str *x, int qm)
{
    char name[48], num[16];
    const char *val = NULL;
    size_t l = 0;
    if (*p == '?' || *p == '$' || *p == '#') {
        int v = *p == '?' ? sh->status : *p == '$' ? (int)getpid() : (sh->nargs > 1 ? sh->nargs - 1 : 0);
        snprintf(num, sizeof num, "%d", v);
        val = num;
        p++;
    } else if (isdigit(*p)) {
        int i = *p++ - '0';
        val = i < sh->nargs ? sh->args[i] : "";
    } else if (*p == '{' && strchr(p, '}')) {
        for (p++; *p != '}' && l < sizeof name - 1; p++)
            name[l++] = *p;
        name[l] = 0;
        while (*p && *p != '}')
            p++;
        p++;
        val = var_get(sh, name);
    } else if (isalpha(*p) || *p == '_') {
        while ((isalpha(*p) || isdigit(*p) || *p == '_') && l < sizeof name - 1)
            name[l++] = *p++;
        name[l] = 0;
        val = var_get(sh, name);
    } else {
        str_put(x, '$', 1);
        return p;
    }
    for (; val && *val; val++)
        str_put(x, *val, (char)qm);
    return p;
}

static int gmatch(const char *p, const char *m, const char *s)
{
    if (!*p)
        return !*s;
    if (*p == '*' && !*m) {
        for (;; s++) {
            if (gmatch(p + 1, m + 1, s))
                return 1;
            if (!*s)
                return 0;
        }
    }
    if (*s && ((*p == '?' && !*m) || *p == *s))
        return gmatch(p + 1, m + 1, s + 1);
    return 0;
}

static int glob_expand(struct str *x, struct av *out)
{
    char *slash = strrchr(x->s, '/');
    size_t dl = slash ? (size_t)(slash - x->s) : 0;
    for (size_t i = 0; i < dl; i++)
        if (!x->m[i] && (x->s[i] == '*' || x->s[i] == '?'))
            return 0;
    char dir[PATH_MAX];
    if (!slash)
        strcpy(dir, ".");
    else if (dl == 0)
        strcpy(dir, "/");
    else
        snprintf(dir, sizeof dir, "%.*s", (int)dl, x->s);
    const char *pat = slash ? slash + 1 : x->s, *pm = x->m + (pat - x->s);
    struct dirent *ents;
    int ne, found = 0;
    if (dir_load(dir, &ents, &ne))
        return 0;
    for (int i = 0; i < ne; i++) {
        const char *nm = ents[i].d_name;
        if (!strcmp(nm, ".") || !strcmp(nm, "..") || (nm[0] == '.' && pat[0] != '.'))
            continue;
        if (gmatch(pat, pm, nm)) {
            size_t pl = slash ? dl + 1 : 0;
            char *full = malloc(pl + strlen(nm) + 1);
            memcpy(full, x->s, pl);
            strcpy(full + pl, nm);
            av_add(out, full);
            found++;
        }
    }
    free(ents);
    return found;
}

static void expand_word(struct shell *sh, const char *raw, struct av *out)
{
    struct str x = { 0, 0, 0, 0 };
    int quoted = 0;
    const char *p = raw;
    if (p[0] == '~' && (p[1] == 0 || p[1] == '/')) {
        const char *h = var_get(sh, "HOME");
        for (h = h ? h : "/"; *h; h++)
            str_put(&x, *h, 1);
        p++;
    }
    while (*p) {
        if (*p == '\'') {
            quoted = 1;
            for (p++; *p && *p != '\''; p++)
                str_put(&x, *p, 1);
            if (*p)
                p++;
        } else if (*p == '"') {
            quoted = 1;
            p++;
            while (*p && *p != '"') {
                if (*p == '\\' && p[1] && strchr("$\"\\", p[1])) {
                    str_put(&x, p[1], 1);
                    p += 2;
                } else if (*p == '$') {
                    p = expand_dollar(sh, p + 1, &x, 1);
                } else {
                    str_put(&x, *p++, 1);
                }
            }
            if (*p)
                p++;
        } else if (*p == '\\' && p[1]) {
            quoted = 1;
            str_put(&x, p[1], 1);
            p += 2;
        } else if (*p == '$') {
            p = expand_dollar(sh, p + 1, &x, 0);
        } else {
            str_put(&x, *p, 0);
            p++;
        }
    }
    if (!x.s) {
        if (!quoted)
            return;                     /* unquoted empty expansion vanishes */
        str_put(&x, 'x', 1);
        x.s[0] = 0;
    } else if (!x.s[0] && !quoted) {
        free(x.s);
        free(x.m);
        return;
    }
    int wild = 0;
    for (size_t i = 0; i < x.n; i++)
        if (!x.m[i] && (x.s[i] == '*' || x.s[i] == '?'))
            wild = 1;
    if (wild && glob_expand(&x, out)) {
        free(x.s);
        free(x.m);
        return;
    }
    free(x.m);
    av_add(out, x.s);
}

/* ---- tokenizer ---- */
enum { T_WORD, T_PIPE, T_AND, T_OR, T_SEMI, T_BG, T_IN, T_OUT, T_APP, T_ERR, T_ERRAPP, T_ERR2OUT };
struct tok {
    int type;
    char *text;
};

static int tokenize(const char *s, struct tok *t, int max)
{
    int n = 0;
    for (;;) {
        while (*s == ' ' || *s == '\t')
            s++;
        if (!*s || *s == '\n' || *s == '#')
            break;
        if (n >= max - 1)
            return -1;
        t[n].text = NULL;
        if (s[0] == '&' && s[1] == '&') {
            t[n++].type = T_AND, s += 2;
        } else if (s[0] == '|' && s[1] == '|') {
            t[n++].type = T_OR, s += 2;
        } else if (*s == '|') {
            t[n++].type = T_PIPE, s++;
        } else if (*s == ';') {
            t[n++].type = T_SEMI, s++;
        } else if (*s == '&') {
            t[n++].type = T_BG, s++;
        } else if (s[0] == '2' && s[1] == '>' && s[2] == '&' && s[3] == '1') {
            t[n++].type = T_ERR2OUT, s += 4;
        } else if (s[0] == '2' && s[1] == '>' && s[2] == '>') {
            t[n++].type = T_ERRAPP, s += 3;
        } else if (s[0] == '2' && s[1] == '>') {
            t[n++].type = T_ERR, s += 2;
        } else if (s[0] == '>' && s[1] == '>') {
            t[n++].type = T_APP, s += 2;
        } else if (*s == '>') {
            t[n++].type = T_OUT, s++;
        } else if (*s == '<') {
            t[n++].type = T_IN, s++;
        } else {
            const char *p = s;
            char q = 0;
            for (; *p; p++) {
                if (q) {
                    if (*p == q)
                        q = 0;
                    else if (q == '"' && *p == '\\' && p[1])
                        p++;
                } else if (*p == '\\' && p[1]) {
                    p++;
                } else if (*p == '\'' || *p == '"') {
                    q = *p;
                } else if (strchr(" \t\n;&|<>", *p)) {
                    break;
                }
            }
            if (q)
                return -2;
            t[n].type = T_WORD;
            t[n++].text = strndup(s, (size_t)(p - s));
            s = p;
        }
    }
    return n;
}

/* ---- execution ---- */
static const char *const SIGNAMES[NSIG] = {
    [SIGHUP] = "HUP", [SIGINT] = "INT", [SIGQUIT] = "QUIT", [SIGILL] = "ILL", [SIGABRT] = "ABRT",
    [SIGFPE] = "FPE", [SIGKILL] = "KILL", [SIGSEGV] = "SEGV", [SIGPIPE] = "PIPE",
    [SIGTERM] = "TERM"
};

static int decode_status(int st)
{
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    int sig = WTERMSIG(st);
    const char *msg = sig == SIGSEGV ? "Segmentation fault" : sig == SIGKILL ? "Killed" :
                      sig == SIGTERM ? "Terminated" : sig == SIGILL ? "Illegal instruction" :
                      sig == SIGFPE ? "Floating point exception" : NULL;
    if (msg)
        dprintf(2, "%s\n", msg);
    return 128 + sig;
}

static int run_line(struct shell *sh, const char *line);
static int run_fd(struct shell *sh, int fd);

static int is_assignment(const char *w)
{
    const char *p = w;
    if (!(isalpha(*p) || *p == '_'))
        return 0;
    while (isalpha(*p) || isdigit(*p) || *p == '_')
        p++;
    return *p == '=';
}

static int try_builtin(struct shell *sh, struct av *av, int *st)
{
    char **a = av->v;
    int n = av->n;
    if (n == 0)
        return 0;
    if (is_assignment(a[0])) {
        for (int i = 0; i < n; i++) {
            char *eq = strchr(a[i], '=');
            if (!is_assignment(a[i]))
                break;
            *eq = 0;
            var_set(sh, a[i], eq + 1, -1);
        }
        *st = 0;
    } else if (!strcmp(a[0], "cd")) {
        const char *d = n > 1 ? a[1] : var_get(sh, "HOME");
        char cwd[PATH_MAX];
        *st = 0;
        if (!d || chdir(d) < 0) {
            dprintf(2, "cd: %s: %s\n", d ? d : "HOME not set", strerror(d ? errno : ENOENT));
            *st = 1;
        } else if (getcwd(cwd, sizeof cwd)) {
            var_set(sh, "PWD", cwd, -1);
        }
    } else if (!strcmp(a[0], "exit")) {
        sh->exiting = 1;
        *st = n > 1 ? (int)strtol(a[1], NULL, 10) : sh->status;
    } else if (!strcmp(a[0], "export")) {
        for (int i = 1; i < n; i++) {
            char *eq = strchr(a[i], '=');
            if (eq) {
                *eq = 0;
                var_set(sh, a[i], eq + 1, 1);
            } else {
                struct var *v = var_find(sh, a[i], strlen(a[i]));
                if (v)
                    v->exp = 1;
                else
                    var_set(sh, a[i], "", 1);
            }
        }
        if (n == 1)
            for (int i = 0; i < sh->nvars; i++)
                if (sh->vars[i].exp)
                    printf("export %s=%s\n", sh->vars[i].name, sh->vars[i].val);
        *st = 0;
    } else if (!strcmp(a[0], "unset")) {
        for (int i = 1; i < n; i++)
            var_unset(sh, a[i]);
        *st = 0;
    } else if (!strcmp(a[0], "set")) {
        for (int i = 0; i < sh->nvars; i++)
            printf("%s=%s\n", sh->vars[i].name, sh->vars[i].val);
        *st = 0;
    } else if (!strcmp(a[0], "wait")) {
        int s;
        while (waitpid(-1, &s, 0) > 0)
            ;
        sh->nbg = 0;
        *st = 0;
    } else if (!strcmp(a[0], ".") || !strcmp(a[0], "source")) {
        int fd = n > 1 ? open(a[1], O_RDONLY) : -1;
        if (fd < 0) {
            dprintf(2, "%s: %s: %s\n", a[0], n > 1 ? a[1] : "(missing file)", strerror(n > 1 ? errno : EINVAL));
            *st = 1;
        } else {
            *st = run_fd(sh, fd);
            close(fd);
        }
    } else if (!strcmp(a[0], "help")) {
        printf("Adico DOS shell (POSIX subset)\n"
               "  built-ins : cd exit export unset set wait . source help\n"
               "  operators : | && || ; & < > >> 2> 2>> 2>&1\n"
               "  expansion : $VAR ${VAR} $? $$ $# $0-$9 ~ * ? and quoting\n"
               "  utilities : ls /bin\n"
               "  keys      : ^C interrupt  ^D end of input  ^U kill line\n");
        *st = 0;
    } else {
        return 0;
    }
    return 1;
}

/* Finds the program through PATH and spawns it. A file that exists but has no
 * executable image (a script) is run by /bin/sh: the ENOEXEC fallback. */
static pid_t spawn_cmd(struct shell *sh, struct av *av, char **env, const struct spawn_attr *at)
{
    const char *cmd = av->v[0], *pv = var_get(sh, "PATH");
    char path[PATH_MAX];
    int err = ENOENT;
    pid_t pid = -1;
    if (strchr(cmd, '/')) {
        snprintf(path, sizeof path, "%s", cmd);
        pid = spawn(path, av->v, env, at);
        err = errno;
    } else {
        for (const char *p = pv ? pv : "/bin"; *p;) {
            const char *e = strchr(p, ':');
            size_t l = e ? (size_t)(e - p) : strlen(p);
            snprintf(path, sizeof path, "%.*s/%s", l ? (int)l : 1, l ? p : ".", cmd);
            pid = spawn(path, av->v, env, at);
            if (pid >= 0)
                return pid;
            if (errno == ENOEXEC) {
                err = ENOEXEC;
                break;
            }
            if (errno != ENOENT)
                err = errno;
            p += l + (e ? 1 : 0);
        }
    }
    if (pid < 0 && err == ENOEXEC) {
        char *sv[MAXTOK];
        int n = 0;
        sv[n++] = "sh";
        sv[n++] = path;
        for (int i = 1; i < av->n && n < MAXTOK - 1; i++)
            sv[n++] = av->v[i];
        sv[n] = NULL;
        pid = spawn("/bin/sh", sv, env, at);
        err = errno;
    }
    if (pid < 0) {
        errno = err;
        dprintf(2, "sh: %s: %s\n", cmd, err == ENOENT ? "command not found" : strerror(err));
    }
    return pid;
}

static int run_pipeline(struct shell *sh, struct tok *t, int lo, int hi, int bg)
{
    pid_t pids[MAXPIPE];
    int np = 0, prev_rd = -1, status = 0, pgid = 0;
    for (int i = lo; i < hi && np < MAXPIPE;) {
        int j = i;
        while (j < hi && t[j].type != T_PIPE)
            j++;
        int last = (j == hi), pfd[2] = { -1, -1 }, in = -1, out = -1, err = -1, e2o = 0, bad = 0;
        struct av av = { 0, 0, 0 };
        if (!last && pipe(pfd) < 0) {
            perror("sh: pipe");
            status = 1;
            break;
        }
        for (int k = i; k < j && !bad; k++) {
            int ty = t[k].type;
            if (ty == T_WORD) {
                expand_word(sh, t[k].text, &av);
            } else if (ty == T_ERR2OUT) {
                e2o = 1;
            } else if (k + 1 >= j || t[k + 1].type != T_WORD) {
                dprintf(2, "sh: syntax error: missing file name after redirection\n");
                bad = 1;
            } else {
                struct av tmp = { 0, 0, 0 };
                expand_word(sh, t[++k].text, &tmp);
                const char *file = tmp.n ? tmp.v[0] : "";
                int fl = (ty == T_IN) ? O_RDONLY : O_WRONLY | O_CREAT | ((ty == T_APP || ty == T_ERRAPP) ? O_APPEND : O_TRUNC);
                int *target = (ty == T_IN) ? &in : (ty == T_OUT || ty == T_APP) ? &out : &err;
                if (*target >= 0)
                    close(*target);
                *target = open(file, fl, 0666);
                if (*target < 0) {
                    dprintf(2, "sh: %s: %s\n", file, strerror(errno));
                    bad = 1;
                }
                av_free(&tmp);
            }
        }
        if (bad) {
            status = 1;
        } else if (av.n == 0) {
            status = 0;                 /* redirections only: files were created */
        } else if (np == 0 && last && !bg && try_builtin(sh, &av, &status)) {
            /* handled inside the shell process */
        } else {
            struct spawn_attr a = { { prev_rd >= 0 ? prev_rd : 0, !last ? pfd[1] : 1, 2 },
                                    !sh->interactive ? 0 : (np == 0 ? -1 : pgid) };
            if (in >= 0)
                a.fd[0] = in;
            if (out >= 0)
                a.fd[1] = out;
            if (err >= 0)
                a.fd[2] = err;
            if (e2o)
                a.fd[2] = a.fd[1];
            char **env = build_env(sh);
            pid_t pid = spawn_cmd(sh, &av, env, &a);
            free_vec(env);
            if (pid > 0) {
                if (np == 0) {
                    pgid = pid;
                    if (!bg && sh->interactive)
                        ioctl(0, TIOCSPGRP, &pgid);
                }
                pids[np++] = pid;
            } else {
                status = errno == ENOENT ? 127 : 126;
            }
        }
        if (prev_rd >= 0)
            close(prev_rd);
        if (pfd[1] >= 0)
            close(pfd[1]);
        if (in >= 0)
            close(in);
        if (out >= 0)
            close(out);
        if (err >= 0)
            close(err);
        prev_rd = pfd[0];
        av_free(&av);
        i = j + 1;
    }
    if (prev_rd >= 0)
        close(prev_rd);
    if (bg) {
        if (np && sh->nbg < 16) {
            sh->bg[sh->nbg++] = pids[np - 1];
            if (sh->interactive)
                printf("[%d] %d\n", sh->nbg, pids[np - 1]);
        }
        return 0;
    }
    for (int k = 0; k < np; k++) {
        int st = 0;
        while (waitpid(pids[k], &st, 0) < 0 && errno == EINTR)
            ;
        if (k == np - 1)
            status = decode_status(st);
        else if (!WIFEXITED(st) && WTERMSIG(st) != SIGPIPE && WTERMSIG(st) != SIGINT)
            decode_status(st);
    }
    if (np && sh->interactive) {
        int me = (int)getpgid(0);
        ioctl(0, TIOCSPGRP, &me);
    }
    return status;
}

static int run_line(struct shell *sh, const char *line)
{
    struct tok t[MAXTOK];
    int n = tokenize(line, t, MAXTOK);
    if (n < 0) {
        dprintf(2, "sh: syntax error: %s\n", n == -2 ? "unterminated quote" : "line too long");
        sh->status = 2;
        n = 0;
    }
    int i = 0, skip = 0;
    while (i < n && !sh->exiting) {
        int j = i;
        while (j < n && t[j].type != T_AND && t[j].type != T_OR && t[j].type != T_SEMI &&
               t[j].type != T_BG)
            j++;
        int op = j < n ? t[j].type : T_SEMI;
        if (j == i) {
            dprintf(2, "sh: syntax error near unexpected token\n");
            sh->status = 2;
            break;
        }
        if (!skip)
            sh->status = run_pipeline(sh, t, i, j, op == T_BG);
        skip = op == T_AND ? sh->status != 0 : op == T_OR ? sh->status == 0 : 0;
        i = j + 1;
    }
    for (int k = 0; k < n; k++)
        free(t[k].text);
    return sh->status;
}

static int run_fd(struct shell *sh, int fd)
{
    struct lr r = { fd, 0, NULL, 0, 0, 0 };
    char *l;
    while (!sh->exiting && (l = lr_next(&r)))
        run_line(sh, l);
    free(r.buf);
    return sh->status;
}

static void reap_jobs(struct shell *sh)
{
    int st;
    pid_t p;
    while ((p = waitpid(-1, &st, WNOHANG)) > 0) {
        for (int k = 0; k < sh->nbg; k++) {
            if (sh->bg[k] == p) {
                printf("[%d] Done (pid %d, status %d)\n", k + 1, p, decode_status(st));
                sh->bg[k] = sh->bg[--sh->nbg];
                break;
            }
        }
    }
}

static void interactive_loop(struct shell *sh)
{
    char line[512], cwd[PATH_MAX];
    sh->interactive = 1;
    sig_ignore(SIGINT, 1);
    int me = (int)getpgid(0);
    ioctl(0, TIOCSPGRP, &me);
    while (!sh->exiting) {
        reap_jobs(sh);
        if (!getcwd(cwd, sizeof cwd))
            strcpy(cwd, "?");
        dprintf(1, "\033[1;32madico\033[0m:\033[1;34m%s\033[0m# ", cwd);
        ssize_t n = read(0, line, sizeof line - 1);
        if (n < 0 && errno == EINTR)
            continue;                   /* ^C at the prompt: show a fresh prompt */
        if (n <= 0) {
            write_all(1, "exit\n", 5);
            break;
        }
        line[n] = 0;
        run_line(sh, line);
    }
}

static int shell_main(int argc, char **argv, char **envp, int is_init)
{
    struct shell *sh = calloc(1, sizeof *sh);
    int rc;
    if (!sh)
        return 1;
    for (int i = 0; envp && envp[i]; i++) {
        char *eq = strchr(envp[i], '=');
        if (eq) {
            char *nm = strndup(envp[i], (size_t)(eq - envp[i]));
            var_set(sh, nm, eq + 1, 1);
            free(nm);
        }
    }
    if (!var_get(sh, "PATH"))
        var_set(sh, "PATH", "/bin", 1);
    sh->args[0] = argv[0];
    sh->nargs = 1;
    int ai = 1;
    if (!is_init && argc > 2 && !strcmp(argv[1], "-c")) {
        sh->args[0] = "sh";
        run_line(sh, argv[2]);
    } else if (!is_init && argc > 1) {
        int fd = open(argv[1], O_RDONLY);
        if (fd < 0) {
            dprintf(2, "sh: %s: %s\n", argv[1], strerror(errno));
            return 127;
        }
        sh->args[0] = argv[1];
        for (ai = 2; ai < argc && sh->nargs < 10; ai++)
            sh->args[sh->nargs++] = argv[ai];
        run_fd(sh, fd);
        close(fd);
    } else if (!isatty(0)) {
        run_fd(sh, 0);
    } else {
        if (is_init) {
            int fd = open("/etc/profile", O_RDONLY);
            if (fd >= 0) {
                run_fd(sh, fd);
                close(fd);
            }
            fd = open("/etc/motd", O_RDONLY);
            if (fd >= 0) {
                char buf[512];
                ssize_t n;
                while ((n = read(fd, buf, sizeof buf)) > 0)
                    write_all(1, buf, (size_t)n);
                close(fd);
            }
        }
        interactive_loop(sh);
    }
    rc = sh->status;
    return rc;
}

PROG(p_sh)
{
    return shell_main(argc, argv, envp, 0);
}

int posix_init_main(int argc, char **argv, char **envp)
{
    return shell_main(argc, argv, envp, 1);
}

/* =========================================================================
 * 5. UTILITIES (installed as /bin/<name>)
 * ========================================================================= */
static int copy_fd(int in, int out)
{
    char buf[2048];
    ssize_t n;
    while ((n = read(in, buf, sizeof buf)) > 0)
        if (write_all(out, buf, (size_t)n) < 0)
            return -1;
    return n < 0 ? -1 : 0;
}

static void out_line(const char *s)
{
    write_all(1, s, strlen(s));
    write_all(1, "\n", 1);
}

PROG(p_true) { return 0; }
PROG(p_false) { return 1; }

PROG(p_echo)
{
    int first = 1, nl = 1;
    if (argc > 1 && !strcmp(argv[1], "-n")) {
        nl = 0;
        first = 2;
    }
    for (int i = first; i < argc; i++) {
        if (i > first)
            write_all(1, " ", 1);
        write_all(1, argv[i], strlen(argv[i]));
    }
    if (nl)
        write_all(1, "\n", 1);
    return 0;
}

PROG(p_cat)
{
    int rc = 0;
    if (argc < 2)
        return copy_fd(0, 1) ? 1 : 0;
    for (int i = 1; i < argc; i++) {
        int fd = !strcmp(argv[i], "-") ? 0 : open(argv[i], O_RDONLY);
        if (fd < 0 || copy_fd(fd, 1) < 0) {
            dprintf(2, "cat: %s: %s\n", argv[i], strerror(errno));
            rc = 1;
        }
        if (fd > 0)
            close(fd);
    }
    return rc;
}

struct lsctx {
    int l, a, tty, col;
};

static void ls_emit(struct lsctx *c, const char *name, const struct stat *st)
{
    if (c->l) {
        char m[11];
        struct tmv tm;
        m[0] = (st->st_mode & S_IFMT) == S_IFDIR ? 'd' : (st->st_mode & S_IFMT) == S_IFCHR ? 'c' : '-';
        for (int i = 0; i < 9; i++)
            m[1 + i] = (st->st_mode & (0400 >> i)) ? "rwxrwxrwx"[i] : '-';
        m[10] = 0;
        gmtime_adico(st->st_mtime, &tm);
        dprintf(1, "%s %2u root %8ld %s %2d %02d:%02d %s\n", m, st->st_nlink, (long)st->st_size,
                MONTHS[(tm.mon + 11) % 12], tm.day, tm.hour, tm.min, name);
    } else if (c->tty) {
        int l = (int)strlen(name) + 2;
        if (c->col + l > 80) {
            write_all(1, "\n", 1);
            c->col = 0;
        }
        dprintf(1, "%s  ", name);
        c->col += l;
    } else {
        out_line(name);
    }
}

static void ls_flush(struct lsctx *c)
{
    if (c->tty && c->col) {
        write_all(1, "\n", 1);
        c->col = 0;
    }
}

static int ls_path(struct lsctx *c, const char *path, int header)
{
    struct stat st;
    struct dirent *e;
    int n;
    if (stat(path, &st) < 0) {
        dprintf(2, "ls: cannot access '%s': %s\n", path, strerror(errno));
        return 1;
    }
    if ((st.st_mode & S_IFMT) != S_IFDIR) {
        ls_emit(c, path, &st);
        ls_flush(c);
        return 0;
    }
    if (dir_load(path, &e, &n)) {
        dprintf(2, "ls: cannot open '%s': %s\n", path, strerror(errno));
        return 1;
    }
    if (header)
        dprintf(1, "%s:\n", path);
    for (int i = 0; i < n; i++) {
        struct stat es;
        char full[PATH_MAX];
        if (!c->a && e[i].d_name[0] == '.')
            continue;
        memset(&es, 0, sizeof es);
        if (c->l) {
            join_path(full, sizeof full, path, e[i].d_name);
            stat(full, &es);
        }
        ls_emit(c, e[i].d_name, &es);
    }
    ls_flush(c);
    free(e);
    return 0;
}

PROG(p_ls)
{
    struct lsctx c = { 0, 0, isatty(1), 0 };
    struct gopt g = { 1, 0, NULL };
    int o, rc = 0;
    while ((o = gopt_next(&g, argc, argv, "la1")) != -1) {
        if (o == 'l')
            c.l = 1;
        else if (o == 'a')
            c.a = 1;
        else if (o == '1')
            c.tty = 0;
        else
            return 2;
    }
    if (g.ind >= argc)
        return ls_path(&c, ".", 0);
    for (int i = g.ind; i < argc; i++)
        rc |= ls_path(&c, argv[i], argc - g.ind > 1);
    return rc;
}

static int mkdirp(const char *path)
{
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof tmp, "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0777);
            *p = '/';
        }
    }
    if (mkdir(tmp, 0777) < 0 && !(errno == EEXIST && is_dir(tmp)))
        return -1;
    return 0;
}

PROG(p_mkdir)
{
    struct gopt g = { 1, 0, NULL };
    int o, p = 0, rc = 0;
    while ((o = gopt_next(&g, argc, argv, "p")) != -1) {
        if (o != 'p')
            return 2;
        p = 1;
    }
    if (g.ind >= argc) {
        dprintf(2, "usage: mkdir [-p] directory...\n");
        return 2;
    }
    for (int i = g.ind; i < argc; i++) {
        if ((p ? mkdirp(argv[i]) : mkdir(argv[i], 0777)) < 0) {
            dprintf(2, "mkdir: cannot create directory '%s': %s\n", argv[i], strerror(errno));
            rc = 1;
        }
    }
    return rc;
}

PROG(p_rmdir)
{
    int rc = 0;
    if (argc < 2) {
        dprintf(2, "usage: rmdir directory...\n");
        return 2;
    }
    for (int i = 1; i < argc; i++) {
        if (rmdir(argv[i]) < 0) {
            dprintf(2, "rmdir: failed to remove '%s': %s\n", argv[i], strerror(errno));
            rc = 1;
        }
    }
    return rc;
}

static int rm_rec(const char *path, int rec, int force)
{
    struct stat st;
    int rc = 0;
    if (stat(path, &st) < 0) {
        if (!force)
            dprintf(2, "rm: cannot remove '%s': %s\n", path, strerror(errno));
        return force ? 0 : 1;
    }
    if ((st.st_mode & S_IFMT) == S_IFDIR) {
        struct dirent *e;
        int n;
        if (!rec) {
            dprintf(2, "rm: cannot remove '%s': Is a directory\n", path);
            return 1;
        }
        if (dir_load(path, &e, &n)) {
            dprintf(2, "rm: cannot open '%s': %s\n", path, strerror(errno));
            return 1;
        }
        for (int i = 0; i < n; i++) {
            char full[PATH_MAX];
            if (!strcmp(e[i].d_name, ".") || !strcmp(e[i].d_name, ".."))
                continue;
            join_path(full, sizeof full, path, e[i].d_name);
            rc |= rm_rec(full, rec, force);
        }
        free(e);
        if (rmdir(path) < 0) {
            dprintf(2, "rm: cannot remove '%s': %s\n", path, strerror(errno));
            rc = 1;
        }
    } else if (unlink(path) < 0) {
        dprintf(2, "rm: cannot remove '%s': %s\n", path, strerror(errno));
        rc = 1;
    }
    return rc;
}

PROG(p_rm)
{
    struct gopt g = { 1, 0, NULL };
    int o, rec = 0, force = 0, rc = 0;
    while ((o = gopt_next(&g, argc, argv, "rRf")) != -1) {
        if (o == 'r' || o == 'R')
            rec = 1;
        else if (o == 'f')
            force = 1;
        else
            return 2;
    }
    if (g.ind >= argc) {
        if (!force)
            dprintf(2, "usage: rm [-rf] file...\n");
        return force ? 0 : 2;
    }
    for (int i = g.ind; i < argc; i++)
        rc |= rm_rec(argv[i], rec, force);
    return rc;
}

static int cp_rec(const char *src, const char *dst, int rec)
{
    struct stat st;
    if (stat(src, &st) < 0) {
        dprintf(2, "cp: cannot stat '%s': %s\n", src, strerror(errno));
        return 1;
    }
    if ((st.st_mode & S_IFMT) == S_IFDIR) {
        struct dirent *e;
        int n, rc = 0;
        if (!rec) {
            dprintf(2, "cp: -r not specified; omitting directory '%s'\n", src);
            return 1;
        }
        if ((mkdir(dst, 0777) < 0 && errno != EEXIST) || dir_load(src, &e, &n)) {
            dprintf(2, "cp: cannot create directory '%s': %s\n", dst, strerror(errno));
            return 1;
        }
        for (int i = 0; i < n; i++) {
            char s2[PATH_MAX], d2[PATH_MAX];
            if (!strcmp(e[i].d_name, ".") || !strcmp(e[i].d_name, ".."))
                continue;
            join_path(s2, sizeof s2, src, e[i].d_name);
            join_path(d2, sizeof d2, dst, e[i].d_name);
            rc |= cp_rec(s2, d2, rec);
        }
        free(e);
        return rc;
    }
    int in = open(src, O_RDONLY), out = in < 0 ? -1 : open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (in < 0 || out < 0 || copy_fd(in, out) < 0) {
        dprintf(2, "cp: cannot copy '%s' to '%s': %s\n", src, dst, strerror(errno));
        if (in >= 0)
            close(in);
        if (out >= 0)
            close(out);
        return 1;
    }
    close(in);
    close(out);
    chmod(dst, st.st_mode & 0777);
    return 0;
}

static int cp_mv(int argc, char **argv, int is_mv)
{
    struct gopt g = { 1, 0, NULL };
    int o, rec = 0, rc = 0;
    while ((o = gopt_next(&g, argc, argv, is_mv ? "f" : "rR")) != -1) {
        if (o == '?')
            return 2;
        rec = (o == 'r' || o == 'R');
    }
    if (argc - g.ind < 2) {
        dprintf(2, "usage: %s %ssource... target\n", argv[0], is_mv ? "" : "[-r] ");
        return 2;
    }
    const char *dst = argv[argc - 1];
    int dir = is_dir(dst);
    if (argc - g.ind > 2 && !dir) {
        dprintf(2, "%s: target '%s' is not a directory\n", argv[0], dst);
        return 1;
    }
    for (int i = g.ind; i < argc - 1; i++) {
        char to[PATH_MAX];
        if (dir)
            join_path(to, sizeof to, dst, base_name(argv[i]));
        else
            snprintf(to, sizeof to, "%s", dst);
        if (is_mv) {
            if (rename(argv[i], to) < 0) {
                dprintf(2, "mv: cannot move '%s' to '%s': %s\n", argv[i], to, strerror(errno));
                rc = 1;
            }
        } else {
            rc |= cp_rec(argv[i], to, rec);
        }
    }
    return rc;
}

PROG(p_cp) { return cp_mv(argc, argv, 0); }
PROG(p_mv) { return cp_mv(argc, argv, 1); }

PROG(p_touch)
{
    int rc = 0;
    for (int i = 1; i < argc; i++) {
        int fd = open(argv[i], O_WRONLY | O_CREAT, 0666);
        if (fd < 0) {
            dprintf(2, "touch: cannot touch '%s': %s\n", argv[i], strerror(errno));
            rc = 1;
        } else {
            write(fd, "", 0);              /* refreshes the modification time */
            close(fd);
        }
    }
    return rc;
}

PROG(p_head)
{
    struct gopt g = { 1, 0, NULL };
    int o, rc = 0;
    long n = 10;
    while ((o = gopt_next(&g, argc, argv, "n:")) != -1) {
        if (o == 'n')
            n = strtol(g.arg, NULL, 10);
        else
            return 2;
    }
    int nf = argc - g.ind;
    for (int i = 0; i < (nf ? nf : 1); i++) {
        const char *name = nf ? argv[g.ind + i] : "-";
        int fd = strcmp(name, "-") ? open(name, O_RDONLY) : 0;
        char buf[1024];
        ssize_t r;
        long lines = 0;
        if (fd < 0) {
            dprintf(2, "head: %s: %s\n", name, strerror(errno));
            rc = 1;
            continue;
        }
        if (nf > 1)
            dprintf(1, "%s==> %s <==\n", i ? "\n" : "", name);
        while (lines < n && (r = read(fd, buf, sizeof buf)) > 0) {
            ssize_t k = 0;
            for (; k < r && lines < n; k++)
                if (buf[k] == '\n')
                    lines++;
            write_all(1, buf, (size_t)k);
        }
        if (fd)
            close(fd);
    }
    return rc;
}

PROG(p_tail)
{
    struct gopt g = { 1, 0, NULL };
    int o, rc = 0;
    long n = 10;
    while ((o = gopt_next(&g, argc, argv, "n:")) != -1) {
        if (o == 'n')
            n = strtol(g.arg, NULL, 10);
        else
            return 2;
    }
    int nf = argc - g.ind;
    for (int i = 0; i < (nf ? nf : 1); i++) {
        const char *name = nf ? argv[g.ind + i] : "-";
        int fd = strcmp(name, "-") ? open(name, O_RDONLY) : 0;
        size_t len = 0;
        char *b = fd < 0 ? NULL : slurp(fd, &len);
        if (!b) {
            dprintf(2, "tail: %s: %s\n", name, strerror(errno));
            rc = 1;
            continue;
        }
        if (fd)
            close(fd);
        if (nf > 1)
            dprintf(1, "%s==> %s <==\n", i ? "\n" : "", name);
        size_t end = len, pos = end;
        long cnt = 0;
        if (end && b[end - 1] == '\n')
            pos = --end + 0;
        while (n > 0 && pos > 0) {
            if (b[pos - 1] == '\n' && ++cnt == n)
                break;
            pos--;
        }
        if (n > 0)
            write_all(1, b + pos, len - pos);
        free(b);
    }
    return rc;
}

PROG(p_wc)
{
    struct gopt g = { 1, 0, NULL };
    int o, fl = 0, rc = 0;
    long tl = 0, tw = 0, tc = 0;
    while ((o = gopt_next(&g, argc, argv, "lwcm")) != -1) {
        if (o == '?')
            return 2;
        fl |= o == 'l' ? 1 : o == 'w' ? 2 : 4;
    }
    if (!fl)
        fl = 7;
    int nf = argc - g.ind;
    for (int i = 0; i < (nf ? nf : 1); i++) {
        const char *name = nf ? argv[g.ind + i] : NULL;
        int fd = name ? open(name, O_RDONLY) : 0, in = 0;
        long l = 0, w = 0, c = 0;
        char buf[1024];
        ssize_t r;
        if (fd < 0) {
            dprintf(2, "wc: %s: %s\n", name, strerror(errno));
            rc = 1;
            continue;
        }
        while ((r = read(fd, buf, sizeof buf)) > 0) {
            for (ssize_t k = 0; k < r; k++) {
                c++;
                if (buf[k] == '\n')
                    l++;
                if (isspace(buf[k]))
                    in = 0;
                else if (!in) {
                    in = 1;
                    w++;
                }
            }
        }
        if (name)
            close(fd);
        tl += l, tw += w, tc += c;
        if (fl & 1)
            printf("%7ld ", l);
        if (fl & 2)
            printf("%7ld ", w);
        if (fl & 4)
            printf("%7ld ", c);
        printf("%s\n", name ? name : "");
    }
    if (nf > 1) {
        if (fl & 1)
            printf("%7ld ", tl);
        if (fl & 2)
            printf("%7ld ", tw);
        if (fl & 4)
            printf("%7ld ", tc);
        printf("total\n");
    }
    return rc;
}

static const char *find_sub(const char *h, const char *n, int ci)
{
    if (!ci)
        return strstr(h, n);
    size_t l = strlen(n);
    for (; *h; h++) {
        size_t i = 0;
        while (i < l && h[i] && tolower(h[i]) == tolower(n[i]))
            i++;
        if (i == l)
            return h;
    }
    return l ? NULL : h;
}

PROG(p_grep)
{
    struct gopt g = { 1, 0, NULL };
    int o, inv = 0, num = 0, cnt = 0, ci = 0, any = 0, rc = 0;
    while ((o = gopt_next(&g, argc, argv, "ivnc")) != -1) {
        if (o == 'i')
            ci = 1;
        else if (o == 'v')
            inv = 1;
        else if (o == 'n')
            num = 1;
        else if (o == 'c')
            cnt = 1;
        else
            return 2;
    }
    if (g.ind >= argc) {
        dprintf(2, "usage: grep [-ivnc] pattern [file...]  (fixed-string match)\n");
        return 2;
    }
    const char *pat = argv[g.ind++];
    int nf = argc - g.ind;
    for (int i = 0; i < (nf ? nf : 1); i++) {
        const char *name = nf ? argv[g.ind + i] : "-";
        struct lr r = { strcmp(name, "-") ? open(name, O_RDONLY) : 0, 0, NULL, 0, 0, 0 };
        char *l;
        long ln = 0, hits = 0;
        if (r.fd < 0) {
            dprintf(2, "grep: %s: %s\n", name, strerror(errno));
            rc = 2;
            continue;
        }
        while ((l = lr_next(&r))) {
            ln++;
            if ((find_sub(l, pat, ci) != NULL) == inv)
                continue;
            hits++;
            any = 1;
            if (cnt)
                continue;
            if (nf > 1)
                dprintf(1, "%s:", name);
            if (num)
                dprintf(1, "%ld:", ln);
            out_line(l);
        }
        if (cnt) {
            if (nf > 1)
                dprintf(1, "%s:", name);
            printf("%ld\n", hits);
        }
        free(r.buf);
        if (r.fd)
            close(r.fd);
    }
    return rc ? rc : (any ? 0 : 1);
}

static int cmp_s(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }
static int cmp_sr(const void *a, const void *b) { return -cmp_s(a, b); }
static int cmp_n(const void *a, const void *b)
{
    long x = strtol(*(char *const *)a, NULL, 10), y = strtol(*(char *const *)b, NULL, 10);
    return x < y ? -1 : x > y;
}
static int cmp_nr(const void *a, const void *b) { return -cmp_n(a, b); }

PROG(p_sort)
{
    struct gopt g = { 1, 0, NULL };
    int o, rev = 0, num = 0, uniq = 0, rc = 0;
    size_t n = 0, cap = 64;
    char **v = malloc(cap * sizeof *v);
    while ((o = gopt_next(&g, argc, argv, "rnu")) != -1) {
        if (o == 'r')
            rev = 1;
        else if (o == 'n')
            num = 1;
        else if (o == 'u')
            uniq = 1;
        else
            return 2;
    }
    int nf = argc - g.ind;
    for (int i = 0; i < (nf ? nf : 1) && v; i++) {
        const char *name = nf ? argv[g.ind + i] : "-";
        struct lr r = { strcmp(name, "-") ? open(name, O_RDONLY) : 0, 0, NULL, 0, 0, 0 };
        char *l;
        if (r.fd < 0) {
            dprintf(2, "sort: %s: %s\n", name, strerror(errno));
            rc = 2;
            continue;
        }
        while ((l = lr_next(&r))) {
            if (n == cap) {
                cap *= 2;
                v = realloc(v, cap * sizeof *v);
            }
            v[n++] = strdup(l);
        }
        free(r.buf);
        if (r.fd)
            close(r.fd);
    }
    qsort(v, n, sizeof *v, num ? (rev ? cmp_nr : cmp_n) : (rev ? cmp_sr : cmp_s));
    for (size_t i = 0; i < n; i++)
        if (!uniq || i == 0 || strcmp(v[i], v[i - 1]))
            out_line(v[i]);
    return rc;
}

PROG(p_uniq)
{
    struct gopt g = { 1, 0, NULL };
    int o, cnt = 0, fd = 0;
    while ((o = gopt_next(&g, argc, argv, "c")) != -1) {
        if (o != 'c')
            return 2;
        cnt = 1;
    }
    if (g.ind < argc && (fd = open(argv[g.ind], O_RDONLY)) < 0) {
        dprintf(2, "uniq: %s: %s\n", argv[g.ind], strerror(errno));
        return 1;
    }
    struct lr r = { fd, 0, NULL, 0, 0, 0 };
    char *l, *prev = NULL;
    long n = 0;
    while ((l = lr_next(&r))) {
        if (prev && !strcmp(prev, l)) {
            n++;
            continue;
        }
        if (prev) {
            if (cnt)
                printf("%7ld ", n);
            out_line(prev);
            free(prev);
        }
        prev = strdup(l);
        n = 1;
    }
    if (prev) {
        if (cnt)
            printf("%7ld ", n);
        out_line(prev);
        free(prev);
    }
    free(r.buf);
    return 0;
}

PROG(p_tee)
{
    struct gopt g = { 1, 0, NULL };
    int o, app = 0, fds[OPEN_MAX], nfd = 0, rc = 0;
    while ((o = gopt_next(&g, argc, argv, "a")) != -1) {
        if (o != 'a')
            return 2;
        app = 1;
    }
    for (int i = g.ind; i < argc && nfd < OPEN_MAX - 4; i++) {
        int fd = open(argv[i], O_WRONLY | O_CREAT | (app ? O_APPEND : O_TRUNC), 0666);
        if (fd < 0) {
            dprintf(2, "tee: %s: %s\n", argv[i], strerror(errno));
            rc = 1;
        } else {
            fds[nfd++] = fd;
        }
    }
    char buf[1024];
    ssize_t n;
    while ((n = read(0, buf, sizeof buf)) > 0) {
        write_all(1, buf, (size_t)n);
        for (int i = 0; i < nfd; i++)
            write_all(fds[i], buf, (size_t)n);
    }
    return rc;
}

PROG(p_sleep)
{
    if (argc != 2 || !isdigit(argv[1][0])) {
        dprintf(2, "usage: sleep seconds\n");
        return 2;
    }
    struct timespec ts = { strtol(argv[1], NULL, 10), 0 };
    return nanosleep(&ts) < 0 ? 1 : 0;
}

PROG(p_yes)
{
    const char *s = argc > 1 ? argv[1] : "y";
    size_t l = strlen(s);
    char *line = malloc(l + 1);
    memcpy(line, s, l);
    line[l] = '\n';
    for (;;)
        if (write_all(1, line, l + 1) < 0)
            return 1;
}

PROG(p_uname)
{
    struct utsname u;
    struct gopt g = { 1, 0, NULL };
    int o, fl = 0;
    uname(&u);
    while ((o = gopt_next(&g, argc, argv, "asnrvm")) != -1) {
        if (o == '?')
            return 2;
        fl |= o == 'a' ? 31 : o == 's' ? 1 : o == 'n' ? 2 : o == 'r' ? 4 : o == 'v' ? 8 : 16;
    }
    if (!fl)
        fl = 1;
    const char *f[] = { u.sysname, u.nodename, u.release, u.version, u.machine };
    for (int i = 0, first = 1; i < 5; i++) {
        if (!(fl & (1 << i)))
            continue;
        printf("%s%s", first ? "" : " ", f[i]);
        first = 0;
    }
    printf("\n");
    return 0;
}

PROG(p_date)
{
    struct tmv tm;
    gmtime_adico(time(), &tm);
    printf("%s %s %2d %02d:%02d:%02d UTC %d\n", WDAYS[tm.wday], MONTHS[(tm.mon + 11) % 12], tm.day,
           tm.hour, tm.min, tm.sec, tm.year);
    return 0;
}

PROG(p_uptime)
{
    struct sysinfo si;
    sysinfo(&si);
    long s = (long)(si.uptime_ticks / HZ);
    printf("up %ld:%02ld:%02ld, %lu processes\n", s / 3600, s / 60 % 60, s % 60, si.nprocs);
    return 0;
}

PROG(p_ps)
{
    struct pinfo pi[32];
    int n = procinfo(pi, 32);
    printf("  PID  PPID  PGID S COMMAND\n");
    for (int i = 0; i < n; i++)
        printf("%5d %5d %5d %c %s\n", pi[i].pid, pi[i].ppid, pi[i].pgid, "?RSZ"[pi[i].state & 3],
               pi[i].name);
    return 0;
}

PROG(p_kill)
{
    int sig = SIGTERM, i = 1, rc = 0;
    if (argc > 1 && argv[1][0] == '-' && argv[1][1]) {
        const char *s = argv[1] + 1;
        i = 2;
        if (!strcmp(s, "s") && argc > 2) {
            s = argv[2];
            i = 3;
        }
        if (!strncmp(s, "SIG", 3))
            s += 3;
        sig = -1;
        if (isdigit(*s))
            sig = (int)strtol(s, NULL, 10);
        else
            for (int k = 1; k < NSIG; k++)
                if (SIGNAMES[k] && !strcmp(SIGNAMES[k], s))
                    sig = k;
        if (sig < 0) {
            dprintf(2, "kill: invalid signal '%s'\n", s);
            return 2;
        }
    }
    if (i >= argc) {
        dprintf(2, "usage: kill [-s SIGNAME | -SIGNAME | -NUMBER] pid...\n");
        return 2;
    }
    for (; i < argc; i++) {
        if (kill((pid_t)strtol(argv[i], NULL, 10), sig) < 0) {
            dprintf(2, "kill: (%s): %s\n", argv[i], strerror(errno));
            rc = 1;
        }
    }
    return rc;
}

PROG(p_free)
{
    struct sysinfo si;
    sysinfo(&si);
    printf("         total      used      free   (KiB)\n");
    printf("Mem: %9lu %9lu %9lu\n", si.mem_total / 1024, (si.mem_total - si.mem_free) / 1024,
           si.mem_free / 1024);
    return 0;
}

PROG(p_df)
{
    struct sysinfo si;
    sysinfo(&si);
    printf("Filesystem   Nodes  BytesInUse\n/ (ramfs) %7lu %11lu\n", si.fs_nodes, si.fs_bytes);
    if (si.disk_sectors)
        printf("disk snapshot capacity: %lu KiB\n", si.disk_sectors / 2);
    else
        printf("disk snapshot: no disk attached\n");
    return 0;
}

PROG(p_stat)
{
    int rc = 0;
    for (int i = 1; i < argc; i++) {
        struct stat st;
        struct tmv tm;
        if (stat(argv[i], &st) < 0) {
            dprintf(2, "stat: cannot stat '%s': %s\n", argv[i], strerror(errno));
            rc = 1;
            continue;
        }
        gmtime_adico(st.st_mtime, &tm);
        const char *ty = (st.st_mode & S_IFMT) == S_IFDIR ? "directory" :
                         (st.st_mode & S_IFMT) == S_IFCHR ? "character device" : "regular file";
        printf("  File: %s\n  Size: %ld  Type: %s\n  Mode: 0%o  Inode: %lu  Links: %u\n"
               "Modify: %04d-%02d-%02d %02d:%02d:%02d UTC\n",
               argv[i], (long)st.st_size, ty, st.st_mode & 0777, st.st_ino, st.st_nlink, tm.year,
               tm.mon, tm.day, tm.hour, tm.min, tm.sec);
    }
    return rc;
}

PROG(p_chmod)
{
    int rc = 0;
    if (argc < 3 || !isdigit(argv[1][0])) {
        dprintf(2, "usage: chmod octal-mode file...\n");
        return 2;
    }
    mode_t m = (mode_t)strtol(argv[1], NULL, 8);
    for (int i = 2; i < argc; i++) {
        if (chmod(argv[i], m) < 0) {
            dprintf(2, "chmod: cannot access '%s': %s\n", argv[i], strerror(errno));
            rc = 1;
        }
    }
    return rc;
}

PROG(p_hd)
{
    int fd = argc > 1 ? open(argv[1], O_RDONLY) : 0;
    u8 b[16];
    long off = 0;
    if (fd < 0) {
        dprintf(2, "hd: %s: %s\n", argv[1], strerror(errno));
        return 1;
    }
    for (;;) {
        int n = 0;
        ssize_t r = 1;
        while (n < 16 && (r = read(fd, b + n, (size_t)(16 - n))) > 0)
            n += (int)r;
        if (n == 0)
            break;
        char ln[128];
        int p = snprintf(ln, sizeof ln, "%08x ", (unsigned)off);
        for (int i = 0; i < 16; i++) {
            if (i == 8)
                ln[p++] = ' ';
            if (i < n)
                p += snprintf(ln + p, 8, " %02x", b[i]);
            else {
                ln[p++] = ' ';
                ln[p++] = ' ';
                ln[p++] = ' ';
            }
        }
        ln[p++] = ' ';
        ln[p++] = ' ';
        ln[p++] = '|';
        for (int i = 0; i < n; i++)
            ln[p++] = (b[i] >= 32 && b[i] < 127) ? (char)b[i] : '.';
        ln[p++] = '|';
        ln[p++] = '\n';
        write_all(1, ln, (size_t)p);
        off += n;
        if (r <= 0 && n < 16)
            break;
    }
    return 0;
}

PROG(p_basename)
{
    if (argc < 2) {
        dprintf(2, "usage: basename string [suffix]\n");
        return 2;
    }
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof tmp, "%s", argv[1]);
    size_t l = strlen(tmp);
    while (l > 1 && tmp[l - 1] == '/')
        tmp[--l] = 0;
    const char *b = l > 1 ? base_name(tmp) : tmp;
    size_t bl = strlen(b);
    if (argc > 2 && strlen(argv[2]) < bl && !strcmp(b + bl - strlen(argv[2]), argv[2]))
        bl -= strlen(argv[2]);
    write_all(1, b, bl);
    write_all(1, "\n", 1);
    return 0;
}

PROG(p_dirname)
{
    if (argc < 2) {
        dprintf(2, "usage: dirname string\n");
        return 2;
    }
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof tmp, "%s", argv[1]);
    size_t l = strlen(tmp);
    while (l > 1 && tmp[l - 1] == '/')
        tmp[--l] = 0;
    char *s = strrchr(tmp, '/');
    if (!s)
        strcpy(tmp, ".");
    else if (s == tmp)
        tmp[1] = 0;
    else
        *s = 0;
    out_line(tmp);
    return 0;
}

PROG(p_seq)
{
    long a = 1, step = 1, z;
    if (argc < 2 || argc > 4) {
        dprintf(2, "usage: seq [first [increment]] last\n");
        return 2;
    }
    z = strtol(argv[argc - 1], NULL, 10);
    if (argc > 2)
        a = strtol(argv[1], NULL, 10);
    if (argc > 3)
        step = strtol(argv[2], NULL, 10);
    if (!step)
        return 1;
    for (long i = a; step > 0 ? i <= z : i >= z; i += step)
        printf("%ld\n", i);
    return 0;
}

PROG(p_env)
{
    for (int i = 0; envp && envp[i]; i++)
        out_line(envp[i]);
    return 0;
}

PROG(p_which)
{
    const char *path = "/bin";
    int rc = 0;
    for (int i = 0; envp && envp[i]; i++)
        if (!strncmp(envp[i], "PATH=", 5))
            path = envp[i] + 5;
    for (int a = 1; a < argc; a++) {
        int found = 0;
        char full[PATH_MAX];
        struct stat st;
        if (strchr(argv[a], '/')) {
            found = stat(argv[a], &st) == 0;
            snprintf(full, sizeof full, "%s", argv[a]);
        }
        for (const char *p = path; !found && *p;) {
            const char *e = strchr(p, ':');
            size_t l = e ? (size_t)(e - p) : strlen(p);
            snprintf(full, sizeof full, "%.*s/%s", (int)l, p, argv[a]);
            found = stat(full, &st) == 0;
            p += l + (e ? 1 : 0);
        }
        if (found)
            out_line(full);
        else
            rc = 1;
    }
    return rc;
}

PROG(p_pwd)
{
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof cwd)) {
        perror("pwd");
        return 1;
    }
    out_line(cwd);
    return 0;
}

PROG(p_clear)
{
    write_all(1, "\033[2J\033[H", 7);
    return 0;
}

PROG(p_sync)
{
    if (sync() < 0) {
        dprintf(2, "sync: %s\n", errno == ENODEV ? "no disk attached" : strerror(errno));
        return 1;
    }
    return 0;
}

PROG(p_poweroff)
{
    reboot_adico(1);
    return 1;
}

PROG(p_reboot)
{
    reboot_adico(2);
    return 1;
}

PROG(p_crash)                           /* demo: a bad access is turned into SIGSEGV */
{
    volatile int *p = (volatile int *)0x200000000UL;
    *p = 1;
    return 0;
}

PROG(p_test)
{
    int br = !strcmp(base_name(argv[0]), "[");
    int n = argc - 1, neg = 0, r;
    char **a = argv + 1;
    struct stat st;
    if (br) {
        if (n < 1 || strcmp(a[n - 1], "]")) {
            dprintf(2, "[: missing ']'\n");
            return 2;
        }
        n--;
    }
    if (n > 0 && !strcmp(a[0], "!")) {
        neg = 1;
        a++;
        n--;
    }
    if (n == 0) {
        r = 0;
    } else if (n == 1) {
        r = a[0][0] != 0;
    } else if (n == 2) {
        const char *op = a[0], *s = a[1];
        int ok = stat(s, &st) == 0;
        if (!strcmp(op, "-z"))
            r = !s[0];
        else if (!strcmp(op, "-n"))
            r = s[0] != 0;
        else if (!strcmp(op, "-e"))
            r = ok;
        else if (!strcmp(op, "-f"))
            r = ok && (st.st_mode & S_IFMT) == S_IFREG;
        else if (!strcmp(op, "-d"))
            r = ok && (st.st_mode & S_IFMT) == S_IFDIR;
        else if (!strcmp(op, "-s"))
            r = ok && st.st_size > 0;
        else if (!strcmp(op, "-r"))
            r = ok && (st.st_mode & 0400);
        else if (!strcmp(op, "-w"))
            r = ok && (st.st_mode & 0200);
        else if (!strcmp(op, "-x"))
            r = ok && (st.st_mode & 0100);
        else {
            dprintf(2, "test: unknown operator '%s'\n", op);
            return 2;
        }
    } else if (n == 3) {
        const char *op = a[1];
        long x = strtol(a[0], NULL, 10), y = strtol(a[2], NULL, 10);
        if (!strcmp(op, "="))
            r = !strcmp(a[0], a[2]);
        else if (!strcmp(op, "!="))
            r = strcmp(a[0], a[2]) != 0;
        else if (!strcmp(op, "-eq"))
            r = x == y;
        else if (!strcmp(op, "-ne"))
            r = x != y;
        else if (!strcmp(op, "-lt"))
            r = x < y;
        else if (!strcmp(op, "-le"))
            r = x <= y;
        else if (!strcmp(op, "-gt"))
            r = x > y;
        else if (!strcmp(op, "-ge"))
            r = x >= y;
        else {
            dprintf(2, "test: unknown operator '%s'\n", op);
            return 2;
        }
    } else {
        dprintf(2, "test: too many arguments\n");
        return 2;
    }
    return (r != 0) == !neg ? 0 : 1;
}

/* =========================================================================
 * 6. PROGRAM TABLE (the kernel installs one /bin entry per row)
 * ========================================================================= */
const struct prog posix_progs[] = {
    { "sh", p_sh }, { "test", p_test }, { "[", p_test }, { "true", p_true }, { "false", p_false },
    { "echo", p_echo }, { "cat", p_cat }, { "ls", p_ls }, { "mkdir", p_mkdir },
    { "rmdir", p_rmdir }, { "rm", p_rm }, { "cp", p_cp }, { "mv", p_mv }, { "touch", p_touch },
    { "head", p_head }, { "tail", p_tail }, { "wc", p_wc }, { "grep", p_grep },
    { "sort", p_sort }, { "uniq", p_uniq }, { "tee", p_tee }, { "sleep", p_sleep },
    { "yes", p_yes }, { "uname", p_uname }, { "date", p_date }, { "uptime", p_uptime },
    { "ps", p_ps }, { "kill", p_kill }, { "free", p_free }, { "df", p_df }, { "stat", p_stat },
    { "chmod", p_chmod }, { "hd", p_hd }, { "basename", p_basename }, { "dirname", p_dirname },
    { "seq", p_seq }, { "env", p_env }, { "which", p_which }, { "pwd", p_pwd },
    { "clear", p_clear }, { "sync", p_sync }, { "poweroff", p_poweroff }, { "halt", p_poweroff },
    { "reboot", p_reboot }, { "crash", p_crash }, { NULL, NULL }
};