#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <ucontext.h>
#include <sys/ucontext.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>

#if !defined(__x86_64__)
#error "retro-sse-emu currently supports x86_64 only"
#endif

#define RETRO_SSE_VERSION "0.10"

typedef union {
    uint8_t  u8[16];
    int8_t   i8[16];
    uint16_t u16[8];
    int16_t  i16[8];
    uint32_t u32[4];
    int32_t  i32[4];
    uint64_t u64[2];
    int64_t  i64[2];
} xmm128_t;

static struct sigaction old_sigill;
static uint8_t altstack_mem[64 * 1024];
static int persistent_fd = -1;
static char proc_name[48] = "?";

static void safe_write_fd(int fd, const void *buf, size_t len) {
    if (fd < 0 || !buf || !len) return;
    ssize_t wr = write(fd, buf, len);
    (void)wr;
}

static void log_raw(const char *s, size_t n) {
    safe_write_fd(STDERR_FILENO, s, n);
    if (persistent_fd >= 0) safe_write_fd(persistent_fd, s, n);
}

static char *append_str(char *p, char *end, const char *s) {
    while (p < end && *s) *p++ = *s++;
    return p;
}

static char *append_u64_hex(char *p, char *end, uint64_t v) {
    static const char h[] = "0123456789abcdef";
    if (p < end) *p++ = '0';
    if (p < end) *p++ = 'x';
    for (int i = 15; i >= 0 && p < end; --i)
        *p++ = h[(v >> (i * 4)) & 0xf];
    return p;
}

static char *append_u64_dec(char *p, char *end, uint64_t v) {
    char tmp[24];
    unsigned n = 0;
    do { tmp[n++] = (char)('0' + (v % 10)); v /= 10; } while (v && n < sizeof(tmp));
    while (n && p < end) *p++ = tmp[--n];
    return p;
}

static char *append_byte_hex(char *p, char *end, uint8_t v) {
    static const char h[] = "0123456789abcdef";
    if (p < end) *p++ = h[v >> 4];
    if (p < end) *p++ = h[v & 15];
    return p;
}

static int open_log_target(const char *path) {
    return open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_DSYNC, 0600);
}

static void init_persistent_log(void) {
    static const char *paths[] = {
        "/mnt/stateful_partition/unencrypted/retro-sse.log",
        "/var/log/retro-sse.log",
        "/tmp/retro-sse.log"
    };
    for (unsigned i = 0; i < sizeof(paths)/sizeof(paths[0]); ++i) {
        int fd = open_log_target(paths[i]);
        if (fd >= 0) { persistent_fd = fd; break; }
    }

    int fd = open("/proc/self/comm", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t n = read(fd, proc_name, sizeof(proc_name) - 1);
        close(fd);
        if (n > 0) {
            while (n > 0 && (proc_name[n-1] == '\n' || proc_name[n-1] == '\r')) n--;
            proc_name[n] = 0;
        }
    }
}

static void log_unsupported(ucontext_t *uc, const uint8_t *ip) {
    char buf[512];
    char *p = buf, *end = buf + sizeof(buf) - 1;
    p = append_str(p, end, "retro-sse v" RETRO_SSE_VERSION ": unsupported SIGILL pid=");
    p = append_u64_dec(p, end, (uint64_t)getpid());
    p = append_str(p, end, " comm=");
    p = append_str(p, end, proc_name);
    p = append_str(p, end, " rip=");
    p = append_u64_hex(p, end, (uint64_t)(uintptr_t)ip);
    p = append_str(p, end, " rflags=");
    p = append_u64_hex(p, end, (uint64_t)uc->uc_mcontext.gregs[REG_EFL]);
    p = append_str(p, end, " bytes=");
    for (int i = 0; i < 15 && p + 3 < end; ++i) {
        p = append_byte_hex(p, end, ip[i]);
        if (p < end) *p++ = ' ';
    }
    if (p < end) *p++ = '\n';
    log_raw(buf, (size_t)(p - buf));
}

static greg_t *gpr_slot(ucontext_t *uc, unsigned reg) {
    static const int idx[16] = {
        REG_RAX, REG_RCX, REG_RDX, REG_RBX,
        REG_RSP, REG_RBP, REG_RSI, REG_RDI,
        REG_R8, REG_R9, REG_R10, REG_R11,
        REG_R12, REG_R13, REG_R14, REG_R15
    };
    if (reg > 15) return NULL;
    return &uc->uc_mcontext.gregs[idx[reg]];
}

static int load_xmm(ucontext_t *uc, unsigned reg, xmm128_t *out) {
    if (!uc->uc_mcontext.fpregs || reg > 15) return -1;
    memcpy(out, &uc->uc_mcontext.fpregs->_xmm[reg], 16);
    return 0;
}

static int store_xmm(ucontext_t *uc, unsigned reg, const xmm128_t *in) {
    if (!uc->uc_mcontext.fpregs || reg > 15) return -1;
    memcpy(&uc->uc_mcontext.fpregs->_xmm[reg], in, 16);
    return 0;
}

struct dec {
    const uint8_t *start;
    const uint8_t *p;
    uint8_t rex;
    uint8_t modrm;
    unsigned mod, reg, rm;
    unsigned p66:1, pf2:1, pf3:1;
};

static int parse_prefixes(struct dec *d, const uint8_t *ip) {
    memset(d, 0, sizeof(*d));
    d->start = ip;
    d->p = ip;
    for (;;) {
        uint8_t b = *d->p;
        if (b == 0x66) { d->p66 = 1; d->p++; continue; }
        if (b == 0xf2) { d->pf2 = 1; d->p++; continue; }
        if (b == 0xf3) { d->pf3 = 1; d->p++; continue; }
        if (b >= 0x40 && b <= 0x4f) { d->rex = b; d->p++; continue; }
        break;
    }
    return 0;
}

static int parse_modrm(struct dec *d) {
    d->modrm = *d->p++;
    d->mod = d->modrm >> 6;
    d->reg = ((d->modrm >> 3) & 7) | ((d->rex & 0x4) ? 8 : 0);
    d->rm  = (d->modrm & 7) | ((d->rex & 0x1) ? 8 : 0);
    return 0;
}

static uintptr_t calc_ea(ucontext_t *uc, struct dec *d, int *ok) {
    *ok = 0;
    if (d->mod == 3) return 0;
    unsigned rm_lo = d->modrm & 7;
    uintptr_t base = 0, index = 0;
    int32_t disp = 0;

    if (rm_lo == 4) {
        uint8_t sib = *d->p++;
        unsigned scale = sib >> 6;
        unsigned idx_lo = (sib >> 3) & 7;
        unsigned base_lo = sib & 7;
        unsigned idx = idx_lo | ((d->rex & 0x2) ? 8 : 0);
        unsigned bas = base_lo | ((d->rex & 0x1) ? 8 : 0);
        if (!(idx_lo == 4 && !(d->rex & 0x2))) {
            greg_t *g = gpr_slot(uc, idx); if (!g) return 0;
            index = ((uintptr_t)*g) << scale;
        }
        if (d->mod == 0 && base_lo == 5) {
            memcpy(&disp, d->p, 4); d->p += 4;
        } else {
            greg_t *g = gpr_slot(uc, bas); if (!g) return 0;
            base = (uintptr_t)*g;
        }
    } else if (d->mod == 0 && rm_lo == 5) {
        memcpy(&disp, d->p, 4); d->p += 4;
        base = (uintptr_t)d->p;
    } else {
        greg_t *g = gpr_slot(uc, d->rm); if (!g) return 0;
        base = (uintptr_t)*g;
    }
    if (d->mod == 1) { int8_t x = *(const int8_t *)d->p; d->p++; disp += x; }
    else if (d->mod == 2) { int32_t x; memcpy(&x, d->p, 4); d->p += 4; disp += x; }
    *ok = 1;
    return base + index + (intptr_t)disp;
}

static uint8_t read_rm8(ucontext_t *uc, struct dec *d, int *ok) {
    if (d->mod != 3) { uintptr_t ea = calc_ea(uc, d, ok); return *ok ? *(volatile uint8_t *)ea : 0; }
    unsigned rm_lo = d->modrm & 7;
    greg_t *g = gpr_slot(uc, d->rm); if (!g) { *ok = 0; return 0; }
    *ok = 1;
    if (!d->rex && rm_lo >= 4 && rm_lo <= 7) {
        greg_t *hg = gpr_slot(uc, rm_lo - 4);
        return (uint8_t)(((uint64_t)*hg >> 8) & 0xff);
    }
    return (uint8_t)((uint64_t)*g & 0xff);
}

static uint16_t read_rm16(ucontext_t *uc, struct dec *d, int *ok) {
    if (d->mod != 3) { uintptr_t ea = calc_ea(uc, d, ok); if (!*ok) return 0; uint16_t v; memcpy(&v,(void*)ea,2); return v; }
    greg_t *g = gpr_slot(uc, d->rm); if (!g) { *ok=0; return 0; } *ok=1; return (uint16_t)*g;
}
static uint32_t read_rm32(ucontext_t *uc, struct dec *d, int *ok) {
    if (d->mod != 3) { uintptr_t ea = calc_ea(uc, d, ok); if (!*ok) return 0; uint32_t v; memcpy(&v,(void*)ea,4); return v; }
    greg_t *g = gpr_slot(uc, d->rm); if (!g) { *ok=0; return 0; } *ok=1; return (uint32_t)*g;
}
static uint64_t read_rm64(ucontext_t *uc, struct dec *d, int *ok) {
    if (d->mod != 3) { uintptr_t ea = calc_ea(uc, d, ok); if (!*ok) return 0; uint64_t v; memcpy(&v,(void*)ea,8); return v; }
    greg_t *g = gpr_slot(uc, d->rm); if (!g) { *ok=0; return 0; } *ok=1; return (uint64_t)*g;
}
static int read_rm128(ucontext_t *uc, struct dec *d, xmm128_t *out) {
    if (d->mod == 3) return load_xmm(uc, d->rm, out);
    int ok=0; uintptr_t ea=calc_ea(uc,d,&ok); if(!ok) return -1; memcpy(out,(void*)ea,16); return 0;
}

static int write_gpr32(ucontext_t *uc, unsigned reg, uint32_t v) {
    greg_t *g=gpr_slot(uc,reg); if(!g) return -1; *g=(greg_t)(uint64_t)v; return 0;
}
static int write_gpr64(ucontext_t *uc, unsigned reg, uint64_t v) {
    greg_t *g=gpr_slot(uc,reg); if(!g) return -1; *g=(greg_t)v; return 0;
}
static int write_rm32(ucontext_t *uc, struct dec *d, uint32_t v) {
    if(d->mod!=3){int ok=0;uintptr_t ea=calc_ea(uc,d,&ok);if(!ok)return-1;memcpy((void*)ea,&v,4);return 0;} return write_gpr32(uc,d->rm,v);
}
static int write_rm64(ucontext_t *uc, struct dec *d, uint64_t v) {
    if(d->mod!=3){int ok=0;uintptr_t ea=calc_ea(uc,d,&ok);if(!ok)return-1;memcpy((void*)ea,&v,8);return 0;} return write_gpr64(uc,d->rm,v);
}
static void set_rip(ucontext_t *uc, const uint8_t *p) { uc->uc_mcontext.gregs[REG_RIP]=(greg_t)(uintptr_t)p; }

static uint32_t popcnt64_soft(uint64_t v) {
    uint32_t c=0; while(v){v&=v-1;c++;} return c;
}
static uint32_t crc32c_byte(uint32_t crc, uint8_t b) {
    crc ^= b;
    for (int i=0;i<8;i++) crc=(crc>>1)^((crc&1)?0x82f63b78u:0u);
    return crc;
}
static uint32_t crc32c_buf(uint32_t crc, uint64_t v, unsigned bytes) {
    for(unsigned i=0;i<bytes;i++){ crc=crc32c_byte(crc,(uint8_t)v); v>>=8; }
    return crc;
}

static int emulate_popcnt(ucontext_t *uc, const uint8_t *ip) {
    struct dec d; parse_prefixes(&d,ip);
    if(!d.pf3 || *d.p++!=0x0f || *d.p++!=0xb8) return 0;
    parse_modrm(&d); int ok=0; uint64_t src;
    if(d.rex&0x08) src=read_rm64(uc,&d,&ok);
    else if(d.p66) src=read_rm16(uc,&d,&ok);
    else src=read_rm32(uc,&d,&ok);
    if(!ok) return 0;
    uint32_t c=popcnt64_soft(src);
    if(d.rex&0x08){ if(write_gpr64(uc,d.reg,c)) return 0; }
    else { if(write_gpr32(uc,d.reg,c)) return 0; }
    greg_t *ef=&uc->uc_mcontext.gregs[REG_EFL];
    uint64_t f=(uint64_t)*ef; const uint64_t mask=(1u<<0)|(1u<<2)|(1u<<4)|(1u<<6)|(1u<<7)|(1u<<11);
    f &= ~mask; if(c==0) f|=(1u<<6); *ef=(greg_t)f;
    set_rip(uc,d.p); return 1;
}

static int emulate_crc32(ucontext_t *uc, const uint8_t *ip) {
    struct dec d; parse_prefixes(&d,ip);
    if(!d.pf2 || *d.p++!=0x0f || *d.p++!=0x38) return 0;
    uint8_t op=*d.p++; if(op!=0xf0 && op!=0xf1) return 0;
    parse_modrm(&d); int ok=0; greg_t *dstg=gpr_slot(uc,d.reg); if(!dstg) return 0;
    uint32_t crc=(uint32_t)*dstg; uint64_t src=0; unsigned bytes=0;
    if(op==0xf0){src=read_rm8(uc,&d,&ok);bytes=1;}
    else if(d.rex&0x08){src=read_rm64(uc,&d,&ok);bytes=8;}
    else if(d.p66){src=read_rm16(uc,&d,&ok);bytes=2;}
    else {src=read_rm32(uc,&d,&ok);bytes=4;}
    if(!ok) return 0;
    uint32_t out=crc32c_buf(crc,src,bytes);
    if(d.rex&0x08) *dstg=(greg_t)(uint64_t)out; else *dstg=(greg_t)(uint64_t)out;
    set_rip(uc,d.p); return 1;
}

static int emulate_pmovx(ucontext_t *uc, struct dec *d, uint8_t op) {
    unsigned src_bytes = 0;
    int is_signed = (op >= 0x20 && op <= 0x25);
    switch (op) {
        case 0x20: case 0x30: src_bytes = 8; break;  /* byte -> word */
        case 0x21: case 0x31: src_bytes = 4; break;  /* byte -> dword */
        case 0x22: case 0x32: src_bytes = 2; break;  /* byte -> qword */
        case 0x23: case 0x33: src_bytes = 8; break;  /* word -> dword */
        case 0x24: case 0x34: src_bytes = 4; break;  /* word -> qword */
        case 0x25: case 0x35: src_bytes = 8; break;  /* dword -> qword */
        default: return 0;
    }

    xmm128_t src, dst;
    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));
    if (d->mod == 3) {
        if (load_xmm(uc, d->rm, &src)) return 0;
    } else {
        int ok = 0;
        uintptr_t ea = calc_ea(uc, d, &ok);
        if (!ok) return 0;
        memcpy(&src, (const void *)ea, src_bytes);
    }

    switch (op) {
        case 0x20: for (int i=0;i<8;i++) dst.i16[i] = is_signed ? (int16_t)src.i8[i] : (int16_t)src.u8[i]; break;
        case 0x21: for (int i=0;i<4;i++) dst.i32[i] = is_signed ? (int32_t)src.i8[i] : (int32_t)src.u8[i]; break;
        case 0x22: for (int i=0;i<2;i++) dst.i64[i] = is_signed ? (int64_t)src.i8[i] : (int64_t)src.u8[i]; break;
        case 0x23: for (int i=0;i<4;i++) dst.i32[i] = is_signed ? (int32_t)src.i16[i] : (int32_t)src.u16[i]; break;
        case 0x24: for (int i=0;i<2;i++) dst.i64[i] = is_signed ? (int64_t)src.i16[i] : (int64_t)src.u16[i]; break;
        case 0x25: for (int i=0;i<2;i++) dst.i64[i] = is_signed ? (int64_t)src.i32[i] : (int64_t)src.u32[i]; break;
        case 0x30: for (int i=0;i<8;i++) dst.u16[i] = src.u8[i]; break;
        case 0x31: for (int i=0;i<4;i++) dst.u32[i] = src.u8[i]; break;
        case 0x32: for (int i=0;i<2;i++) dst.u64[i] = src.u8[i]; break;
        case 0x33: for (int i=0;i<4;i++) dst.u32[i] = src.u16[i]; break;
        case 0x34: for (int i=0;i<2;i++) dst.u64[i] = src.u16[i]; break;
        case 0x35: for (int i=0;i<2;i++) dst.u64[i] = src.u32[i]; break;
        default: return 0;
    }
    if (store_xmm(uc, d->reg, &dst)) return 0;
    set_rip(uc, d->p);
    return 1;
}


static uint32_t roundss_soft_bits(uint32_t bits, unsigned mode) {
    uint32_t sign = bits & 0x80000000u;
    uint32_t absb = bits & 0x7fffffffu;
    unsigned exp = (absb >> 23) & 0xffu;
    uint32_t frac = absb & 0x7fffffu;

    /* NaN/Inf and values already integral at float precision. */
    if (exp == 0xffu) return bits;
    int e = (int)exp - 127;
    if (e >= 23) return bits;
    if (absb == 0) return bits;

    if (e < 0) {
        switch (mode & 3u) {
            case 0: /* nearest, ties to even */
                if (e < -1) return sign;
                /* e == -1: exactly 0.5 has frac==0 and rounds to even 0. */
                return frac ? (sign | 0x3f800000u) : sign;
            case 1: /* floor */
                return sign ? 0xbf800000u : 0x00000000u;
            case 2: /* ceil */
                return sign ? 0x80000000u : 0x3f800000u;
            case 3: /* truncate */
            default:
                return sign;
        }
    }

    unsigned frac_bits = 23u - (unsigned)e;
    uint32_t mask = (1u << frac_bits) - 1u;
    uint32_t discarded = absb & mask;
    if (!discarded) return bits;
    uint32_t base = absb & ~mask;
    uint32_t step = 1u << frac_bits;

    switch (mode & 3u) {
        case 0: { /* nearest, ties to even */
            uint32_t half = step >> 1;
            if (discarded > half ||
                (discarded == half && (base & step)))
                base += step;
            break;
        }
        case 1: /* floor */
            if (sign) base += step;
            break;
        case 2: /* ceil */
            if (!sign) base += step;
            break;
        case 3: /* truncate */
        default:
            break;
    }
    return sign | base;
}


static int read_rm32_xmm_bits(ucontext_t *uc, struct dec *d, uint32_t *out);

static uint64_t roundsd_soft_bits(uint64_t bits, unsigned mode) {
    uint64_t sign = bits & 0x8000000000000000ull;
    uint64_t absb = bits & 0x7fffffffffffffffull;
    unsigned exp = (unsigned)((absb >> 52) & 0x7ffu);
    uint64_t frac = absb & 0x000fffffffffffffull;
    if (exp == 0x7ffu) return bits;
    int e = (int)exp - 1023;
    if (e >= 52) return bits;
    if (absb == 0) return bits;
    if (e < 0) {
        switch (mode & 3u) {
            case 0:
                if (e < -1) return sign;
                return frac ? (sign | 0x3ff0000000000000ull) : sign;
            case 1: return sign ? 0xbff0000000000000ull : 0ull;
            case 2: return sign ? 0x8000000000000000ull : 0x3ff0000000000000ull;
            default: return sign;
        }
    }
    unsigned frac_bits = 52u - (unsigned)e;
    uint64_t mask = (1ull << frac_bits) - 1ull;
    uint64_t discarded = absb & mask;
    if (!discarded) return bits;
    uint64_t base = absb & ~mask;
    uint64_t step = 1ull << frac_bits;
    switch (mode & 3u) {
        case 0: {
            uint64_t half = step >> 1;
            if (discarded > half || (discarded == half && (base & step))) base += step;
            break;
        }
        case 1: if (sign) base += step; break;
        case 2: if (!sign) base += step; break;
        default: break;
    }
    return sign | base;
}

static unsigned sse_round_mode(ucontext_t *uc, uint8_t imm) {
    if (imm & 0x04) {
        if (!uc->uc_mcontext.fpregs) return 0;
        return (uc->uc_mcontext.fpregs->mxcsr >> 13) & 3u;
    }
    return imm & 3u;
}

static int read_rm64_xmm_bits(ucontext_t *uc, struct dec *d, uint64_t *out) {
    if (d->mod == 3) {
        xmm128_t x;
        if (load_xmm(uc, d->rm, &x)) return -1;
        *out = x.u64[0];
        return 0;
    }
    int ok = 0;
    uintptr_t ea = calc_ea(uc, d, &ok);
    if (!ok) return -1;
    memcpy(out, (const void *)ea, sizeof(*out));
    return 0;
}

static int emulate_round_any(ucontext_t *uc, struct dec *d, uint8_t op) {
    xmm128_t dst, src;
    if (load_xmm(uc, d->reg, &dst)) return 0;
    if (op == 0x0a) { /* ROUNDSS */
        uint32_t b;
        if (read_rm32_xmm_bits(uc, d, &b)) return 0;
        uint8_t imm = *d->p++;
        dst.u32[0] = roundss_soft_bits(b, sse_round_mode(uc, imm));
    } else if (op == 0x0b) { /* ROUNDSD */
        uint64_t b;
        if (read_rm64_xmm_bits(uc, d, &b)) return 0;
        uint8_t imm = *d->p++;
        dst.u64[0] = roundsd_soft_bits(b, sse_round_mode(uc, imm));
    } else {
        if (read_rm128(uc, d, &src)) return 0;
        uint8_t imm = *d->p++;
        unsigned mode = sse_round_mode(uc, imm);
        if (op == 0x08) for (int i=0;i<4;i++) dst.u32[i] = roundss_soft_bits(src.u32[i], mode);
        else if (op == 0x09) for (int i=0;i<2;i++) dst.u64[i] = roundsd_soft_bits(src.u64[i], mode);
        else return 0;
    }
    if (store_xmm(uc, d->reg, &dst)) return 0;
    set_rip(uc, d->p);
    return 1;
}

static int emulate_pcmpistri(ucontext_t *uc, struct dec *d) {
    xmm128_t a, b;
    if (load_xmm(uc, d->reg, &a) || read_rm128(uc, d, &b)) return 0;
    uint8_t imm = *d->p++;
    unsigned words = imm & 1u;
    unsigned signed_elems = (imm >> 1) & 1u;
    unsigned agg = (imm >> 2) & 3u;
    unsigned pol = (imm >> 4) & 3u;
    unsigned msb_index = (imm >> 6) & 1u;
    unsigned n = words ? 8u : 16u;
    unsigned la=n, lb=n;
    if (words) {
        for (unsigned i=0;i<n;i++) if (a.u16[i]==0) { la=i; break; }
        for (unsigned i=0;i<n;i++) if (b.u16[i]==0) { lb=i; break; }
    } else {
        for (unsigned i=0;i<n;i++) if (a.u8[i]==0) { la=i; break; }
        for (unsigned i=0;i<n;i++) if (b.u8[i]==0) { lb=i; break; }
    }
    uint32_t valid_mask = (n==16 ? 0xffffu : 0xffu);
    uint32_t int1 = 0;
    if (agg == 0) { /* equal any */
        for (unsigned j=0;j<n;j++) if (j<lb) {
            int hit=0;
            for (unsigned i=0;i<la && !hit;i++) {
                if (words) hit = (a.u16[i] == b.u16[j]);
                else hit = (a.u8[i] == b.u8[j]);
            }
            if (hit) int1 |= 1u<<j;
        }
    } else if (agg == 1) { /* ranges: A pairs are low/high */
        for (unsigned j=0;j<n;j++) if (j<lb) {
            int hit=0;
            for (unsigned i=0;i+1<la && !hit;i+=2) {
                if (words) {
                    if (signed_elems) { int16_t v=b.i16[j], lo=a.i16[i], hi=a.i16[i+1]; hit=(v>=lo && v<=hi); }
                    else { uint16_t v=b.u16[j], lo=a.u16[i], hi=a.u16[i+1]; hit=(v>=lo && v<=hi); }
                } else {
                    if (signed_elems) { int8_t v=b.i8[j], lo=a.i8[i], hi=a.i8[i+1]; hit=(v>=lo && v<=hi); }
                    else { uint8_t v=b.u8[j], lo=a.u8[i], hi=a.u8[i+1]; hit=(v>=lo && v<=hi); }
                }
            }
            if (hit) int1 |= 1u<<j;
        }
    } else if (agg == 2) { /* equal each */
        for (unsigned i=0;i<n;i++) {
            int va=i<la, vb=i<lb;
            int eq;
            if (!va && !vb) eq=1;
            else if (!va || !vb) eq=0;
            else eq = words ? (a.u16[i]==b.u16[i]) : (a.u8[i]==b.u8[i]);
            if (eq) int1 |= 1u<<i;
        }
    } else { /* equal ordered: A substring in B starting at each position */
        for (unsigned j=0;j<n;j++) {
            int ok=1;
            for (unsigned i=0;i<la;i++) {
                if (j+i >= lb) { ok=0; break; }
                if (words ? (a.u16[i]!=b.u16[j+i]) : (a.u8[i]!=b.u8[j+i])) { ok=0; break; }
            }
            if (ok) int1 |= 1u<<j;
        }
    }
    uint32_t mask_b = lb>=n ? valid_mask : ((1u<<lb)-1u);
    uint32_t int2;
    if (pol == 0) int2=int1;
    else if (pol == 1) int2=(~int1)&valid_mask;
    else if (pol == 2) int2=int1 & mask_b;
    else int2=(~int1) & mask_b;

    uint32_t idx=n;
    if (int2) {
        if (!msb_index) { for (unsigned i=0;i<n;i++) if (int2&(1u<<i)) { idx=i; break; } }
        else { for (int i=(int)n-1;i>=0;i--) if (int2&(1u<<i)) { idx=(uint32_t)i; break; } }
    }
    if (write_gpr32(uc, 1, idx)) return 0; /* ECX */
    greg_t *ef=&uc->uc_mcontext.gregs[REG_EFL];
    uint64_t f=(uint64_t)*ef;
    const uint64_t M=(1u<<0)|(1u<<2)|(1u<<4)|(1u<<6)|(1u<<7)|(1u<<11);
    f &= ~M;
    if (int2) f |= 1u<<0;        /* CF */
    if (lb < n) f |= 1u<<6;      /* ZF */
    if (la < n) f |= 1u<<7;      /* SF */
    if (int2 & 1u) f |= 1u<<11;  /* OF */
    *ef=(greg_t)f;
    set_rip(uc, d->p);
    return 1;
}

static int read_rm32_xmm_bits(ucontext_t *uc, struct dec *d, uint32_t *out) {
    if (d->mod == 3) {
        xmm128_t x;
        if (load_xmm(uc, d->rm, &x)) return -1;
        *out = x.u32[0];
        return 0;
    }
    int ok = 0;
    uintptr_t ea = calc_ea(uc, d, &ok);
    if (!ok) return -1;
    memcpy(out, (const void *)ea, sizeof(*out));
    return 0;
}


/* ---- AES-NI / PCLMULQDQ software fallback (v0.10) ---- */
static const uint8_t aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static const uint8_t aes_inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

static uint8_t aes_xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80u) ? 0x1bu : 0u));
}

static uint8_t aes_mul2(uint8_t x)  { return aes_xtime(x); }
static uint8_t aes_mul3(uint8_t x)  { return (uint8_t)(aes_xtime(x) ^ x); }
static uint8_t aes_mul4(uint8_t x)  { return aes_xtime(aes_xtime(x)); }
static uint8_t aes_mul8(uint8_t x)  { return aes_xtime(aes_mul4(x)); }
static uint8_t aes_mul9(uint8_t x)  { return (uint8_t)(aes_mul8(x) ^ x); }
static uint8_t aes_mul11(uint8_t x) { return (uint8_t)(aes_mul8(x) ^ aes_mul2(x) ^ x); }
static uint8_t aes_mul13(uint8_t x) { return (uint8_t)(aes_mul8(x) ^ aes_mul4(x) ^ x); }
static uint8_t aes_mul14(uint8_t x) { return (uint8_t)(aes_mul8(x) ^ aes_mul4(x) ^ aes_mul2(x)); }

static void aes_shift_rows(uint8_t out[16], const uint8_t in[16]) {
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            out[r + 4*c] = in[r + 4*((c + r) & 3)];
}

static void aes_inv_shift_rows(uint8_t out[16], const uint8_t in[16]) {
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            out[r + 4*c] = in[r + 4*((c - r + 4) & 3)];
}

static void aes_mix_columns(uint8_t out[16], const uint8_t in[16]) {
    for (int c = 0; c < 4; ++c) {
        int i = 4*c;
        uint8_t a0=in[i], a1=in[i+1], a2=in[i+2], a3=in[i+3];
        out[i]   = (uint8_t)(aes_mul2(a0) ^ aes_mul3(a1) ^ a2 ^ a3);
        out[i+1] = (uint8_t)(a0 ^ aes_mul2(a1) ^ aes_mul3(a2) ^ a3);
        out[i+2] = (uint8_t)(a0 ^ a1 ^ aes_mul2(a2) ^ aes_mul3(a3));
        out[i+3] = (uint8_t)(aes_mul3(a0) ^ a1 ^ a2 ^ aes_mul2(a3));
    }
}

static void aes_inv_mix_columns(uint8_t out[16], const uint8_t in[16]) {
    for (int c = 0; c < 4; ++c) {
        int i = 4*c;
        uint8_t a0=in[i], a1=in[i+1], a2=in[i+2], a3=in[i+3];
        out[i]   = (uint8_t)(aes_mul14(a0) ^ aes_mul11(a1) ^ aes_mul13(a2) ^ aes_mul9(a3));
        out[i+1] = (uint8_t)(aes_mul9(a0) ^ aes_mul14(a1) ^ aes_mul11(a2) ^ aes_mul13(a3));
        out[i+2] = (uint8_t)(aes_mul13(a0) ^ aes_mul9(a1) ^ aes_mul14(a2) ^ aes_mul11(a3));
        out[i+3] = (uint8_t)(aes_mul11(a0) ^ aes_mul13(a1) ^ aes_mul9(a2) ^ aes_mul14(a3));
    }
}

static int emulate_aes_round(ucontext_t *uc, struct dec *d, uint8_t op) {
    xmm128_t dst, src, tmp1, tmp2;
    if (load_xmm(uc, d->reg, &dst) || read_rm128(uc, d, &src)) return 0;

    if (op == 0xdc || op == 0xdd) { /* AESENC / AESENCLAST */
        for (int i=0;i<16;i++) tmp1.u8[i] = aes_sbox[dst.u8[i]];
        aes_shift_rows(tmp2.u8, tmp1.u8);
        if (op == 0xdc) aes_mix_columns(tmp1.u8, tmp2.u8);
        else memcpy(tmp1.u8, tmp2.u8, 16);
    } else if (op == 0xde || op == 0xdf) { /* AESDEC / AESDECLAST */
        aes_inv_shift_rows(tmp1.u8, dst.u8);
        for (int i=0;i<16;i++) tmp2.u8[i] = aes_inv_sbox[tmp1.u8[i]];
        if (op == 0xde) aes_inv_mix_columns(tmp1.u8, tmp2.u8);
        else memcpy(tmp1.u8, tmp2.u8, 16);
    } else {
        return 0;
    }

    for (int i=0;i<16;i++) dst.u8[i] = (uint8_t)(tmp1.u8[i] ^ src.u8[i]);
    if (store_xmm(uc, d->reg, &dst)) return 0;
    set_rip(uc, d->p);
    return 1;
}

static int emulate_aesimc(ucontext_t *uc, struct dec *d) {
    xmm128_t src, dst;
    if (read_rm128(uc, d, &src)) return 0;
    aes_inv_mix_columns(dst.u8, src.u8);
    if (store_xmm(uc, d->reg, &dst)) return 0;
    set_rip(uc, d->p);
    return 1;
}

static uint32_t aes_subword(uint32_t x) {
    return (uint32_t)aes_sbox[x & 0xffu] |
           ((uint32_t)aes_sbox[(x >> 8) & 0xffu] << 8) |
           ((uint32_t)aes_sbox[(x >> 16) & 0xffu] << 16) |
           ((uint32_t)aes_sbox[(x >> 24) & 0xffu] << 24);
}

static uint32_t aes_rotword_le(uint32_t x) {
    return (x >> 8) | (x << 24);
}

static int emulate_aeskeygenassist(ucontext_t *uc, struct dec *d) {
    xmm128_t src, dst;
    if (read_rm128(uc, d, &src)) return 0;
    uint8_t imm = *d->p++;

    uint32_t t2 = aes_subword(src.u32[1]);
    uint32_t t1 = aes_subword(src.u32[3]);
    dst.u32[0] = t2;
    dst.u32[1] = aes_rotword_le(t2) ^ (uint32_t)imm;
    dst.u32[2] = t1;
    dst.u32[3] = aes_rotword_le(t1) ^ (uint32_t)imm;

    if (store_xmm(uc, d->reg, &dst)) return 0;
    set_rip(uc, d->p);
    return 1;
}

static int emulate_pclmulqdq(ucontext_t *uc, struct dec *d) {
    xmm128_t dst, src, out;
    if (load_xmm(uc, d->reg, &dst) || read_rm128(uc, d, &src)) return 0;
    uint8_t imm = *d->p++;

    uint64_t a = dst.u64[(imm >> 0) & 1u];
    uint64_t b = src.u64[(imm >> 4) & 1u];
    uint64_t lo = 0, hi = 0;

    for (unsigned i=0;i<64;i++) {
        if ((b >> i) & 1u) {
            if (i == 0) {
                lo ^= a;
            } else {
                lo ^= a << i;
                hi ^= a >> (64u - i);
            }
        }
    }

    out.u64[0] = lo;
    out.u64[1] = hi;
    if (store_xmm(uc, d->reg, &out)) return 0;
    set_rip(uc, d->p);
    return 1;
}


static int emulate_sse4(ucontext_t *uc, const uint8_t *ip) {
    struct dec d; parse_prefixes(&d,ip);
    if(!d.p66 || *d.p++!=0x0f) return 0;
    uint8_t map=*d.p++;

    if(map==0x3a){
        uint8_t op=*d.p++;
        if(!(op==0x08||op==0x09||op==0x0a||op==0x0b||op==0x14||op==0x16||op==0x17||op==0x20||op==0x21||op==0x22||op==0x0c||op==0x0d||op==0x0e||op==0x44||op==0x63||op==0xdf)) return 0;
        parse_modrm(&d);
        if(op>=0x08 && op<=0x0b) return emulate_round_any(uc,&d,op);
        if(op==0x44) return emulate_pclmulqdq(uc,&d);
        if(op==0x63) return emulate_pcmpistri(uc,&d);
        if(op==0xdf) return emulate_aeskeygenassist(uc,&d);
        if(op==0x17){xmm128_t x;if(load_xmm(uc,d.reg,&x))return 0;uint8_t imm;uint32_t v;if(d.mod==3){imm=*d.p++;v=x.u32[imm&3];if(write_rm32(uc,&d,v))return 0;}else{int ok=0;uintptr_t ea=calc_ea(uc,&d,&ok);if(!ok)return 0;imm=*d.p++;v=x.u32[imm&3];memcpy((void*)ea,&v,4);}set_rip(uc,d.p);return 1;}
        if(op==0x21){xmm128_t dst,src;if(load_xmm(uc,d.reg,&dst))return 0;uint8_t imm;if(d.mod==3){if(load_xmm(uc,d.rm,&src))return 0;imm=*d.p++;dst.u32[(imm>>4)&3]=src.u32[(imm>>6)&3];}else{int ok=0;uintptr_t ea=calc_ea(uc,&d,&ok);if(!ok)return 0;uint32_t v;memcpy(&v,(void*)ea,4);imm=*d.p++;dst.u32[(imm>>4)&3]=v;}for(int i=0;i<4;i++)if(imm&(1u<<i))dst.u32[i]=0;if(store_xmm(uc,d.reg,&dst))return 0;set_rip(uc,d.p);return 1;}
        if(op==0x20){int ok=0;uint8_t src=read_rm8(uc,&d,&ok);if(!ok)return 0;uint8_t imm=*d.p++;xmm128_t x;if(load_xmm(uc,d.reg,&x))return 0;x.u8[imm&15]=src;if(store_xmm(uc,d.reg,&x))return 0;set_rip(uc,d.p);return 1;}
        if(op==0x22){int ok=0;xmm128_t x;if(load_xmm(uc,d.reg,&x))return 0;if(d.rex&8){uint64_t src=read_rm64(uc,&d,&ok);if(!ok)return 0;uint8_t imm=*d.p++;x.u64[imm&1]=src;}else{uint32_t src=read_rm32(uc,&d,&ok);if(!ok)return 0;uint8_t imm=*d.p++;x.u32[imm&3]=src;}if(store_xmm(uc,d.reg,&x))return 0;set_rip(uc,d.p);return 1;}
        if(op==0x14){uint8_t imm;xmm128_t x;if(load_xmm(uc,d.reg,&x))return 0;if(d.mod==3){imm=*d.p++;greg_t*g=gpr_slot(uc,d.rm);if(!g)return 0;*g=(greg_t)(uint64_t)x.u8[imm&15];}else{int ok=0;uintptr_t ea=calc_ea(uc,&d,&ok);if(!ok)return 0;imm=*d.p++;*(volatile uint8_t*)ea=x.u8[imm&15];}set_rip(uc,d.p);return 1;}
        if(op==0x16){uint8_t imm;xmm128_t x;if(load_xmm(uc,d.reg,&x))return 0;if(d.mod==3){imm=*d.p++;if(d.rex&8){if(write_rm64(uc,&d,x.u64[imm&1]))return 0;}else{if(write_rm32(uc,&d,x.u32[imm&3]))return 0;}}else{int ok=0;uintptr_t ea=calc_ea(uc,&d,&ok);if(!ok)return 0;imm=*d.p++;if(d.rex&8){uint64_t v=x.u64[imm&1];memcpy((void*)ea,&v,8);}else{uint32_t v=x.u32[imm&3];memcpy((void*)ea,&v,4);}}set_rip(uc,d.p);return 1;}
        if(op==0x0c||op==0x0d||op==0x0e){xmm128_t dst,src;if(load_xmm(uc,d.reg,&dst)||read_rm128(uc,&d,&src))return 0;uint8_t imm=*d.p++;if(op==0x0c){for(int i=0;i<4;i++)if(imm&(1u<<i))dst.u32[i]=src.u32[i];}else if(op==0x0d){for(int i=0;i<2;i++)if(imm&(1u<<i))dst.u64[i]=src.u64[i];}else{for(int i=0;i<8;i++)if(imm&(1u<<i))dst.u16[i]=src.u16[i];}if(store_xmm(uc,d.reg,&dst))return 0;set_rip(uc,d.p);return 1;}
    }

    if(map==0x38){
        uint8_t op=*d.p++;
        parse_modrm(&d);
        if (op == 0xdb) return emulate_aesimc(uc, &d);
        if (op >= 0xdc && op <= 0xdf) return emulate_aes_round(uc, &d, op);
        if ((op >= 0x20 && op <= 0x25) || (op >= 0x30 && op <= 0x35))
            return emulate_pmovx(uc, &d, op);
        xmm128_t dst,src;
        if(load_xmm(uc,d.reg,&dst)||read_rm128(uc,&d,&src)) return 0;
        switch(op){
            case 0x10:{xmm128_t mask;if(load_xmm(uc,0,&mask))return 0;for(int i=0;i<16;i++)if(mask.u8[i]&0x80)dst.u8[i]=src.u8[i];break;}
            case 0x14:{xmm128_t mask;if(load_xmm(uc,0,&mask))return 0;for(int i=0;i<4;i++)if(mask.u32[i]&0x80000000u)dst.u32[i]=src.u32[i];break;}
            case 0x15:{xmm128_t mask;if(load_xmm(uc,0,&mask))return 0;for(int i=0;i<2;i++)if(mask.u64[i]&0x8000000000000000ull)dst.u64[i]=src.u64[i];break;}
            case 0x17:{uint64_t a=(dst.u64[0]&src.u64[0])|(dst.u64[1]&src.u64[1]);uint64_t b=((~dst.u64[0])&src.u64[0])|((~dst.u64[1])&src.u64[1]);greg_t*ef=&uc->uc_mcontext.gregs[REG_EFL];uint64_t f=(uint64_t)*ef;const uint64_t M=(1u<<0)|(1u<<2)|(1u<<4)|(1u<<6)|(1u<<7)|(1u<<11);f&=~M;if(!a)f|=1u<<6;if(!b)f|=1u<<0;*ef=(greg_t)f;break;}
            case 0x28: for(int i=0;i<2;i++) dst.i64[i]=(int64_t)dst.i32[i*2]*(int64_t)src.i32[i*2]; break;
            case 0x29: for(int i=0;i<2;i++) dst.u64[i]=(dst.u64[i]==src.u64[i])?UINT64_MAX:0; break;
            case 0x2a: dst=src; break; /* MOVNTDQA */
            case 0x2b:{xmm128_t r;for(int i=0;i<4;i++){int32_t a=dst.i32[i],b=src.i32[i];uint32_t ua=(a<0)?0u:(a>65535?65535u:(uint32_t)a);uint32_t ub=(b<0)?0u:(b>65535?65535u:(uint32_t)b);r.u16[i]=(uint16_t)ua;r.u16[i+4]=(uint16_t)ub;}dst=r;break;}
            case 0x37: for(int i=0;i<2;i++) dst.u64[i]=(dst.i64[i]>src.i64[i])?UINT64_MAX:0; break;
            case 0x38: for(int i=0;i<16;i++) if(src.i8[i]<dst.i8[i]) dst.i8[i]=src.i8[i]; break;
            case 0x39: for(int i=0;i<4;i++) if(src.i32[i]<dst.i32[i]) dst.i32[i]=src.i32[i]; break;
            case 0x3a: for(int i=0;i<8;i++) if(src.u16[i]<dst.u16[i]) dst.u16[i]=src.u16[i]; break;
            case 0x3b: for(int i=0;i<4;i++) if(src.u32[i]<dst.u32[i]) dst.u32[i]=src.u32[i]; break;
            case 0x3c: for(int i=0;i<16;i++) if(src.i8[i]>dst.i8[i]) dst.i8[i]=src.i8[i]; break;
            case 0x3d: for(int i=0;i<4;i++) if(src.i32[i]>dst.i32[i]) dst.i32[i]=src.i32[i]; break;
            case 0x3e: for(int i=0;i<8;i++) if(src.u16[i]>dst.u16[i]) dst.u16[i]=src.u16[i]; break;
            case 0x3f: for(int i=0;i<4;i++) if(src.u32[i]>dst.u32[i]) dst.u32[i]=src.u32[i]; break;
            case 0x40: for(int i=0;i<4;i++) dst.u32[i]=(uint32_t)((uint64_t)dst.u32[i]*(uint64_t)src.u32[i]); break;
            case 0x41:{uint16_t minv=src.u16[0],idx=0;for(uint16_t i=1;i<8;i++)if(src.u16[i]<minv){minv=src.u16[i];idx=i;}memset(&dst,0,sizeof(dst));dst.u16[0]=minv;dst.u16[1]=idx;break;}
            default: return 0;
        }
        if(op!=0x17 && store_xmm(uc,d.reg,&dst)) return 0;
        set_rip(uc,d.p); return 1;
    }
    return 0;
}

static void dispatch_downstream_sigill(int sig, siginfo_t *si, void *vctx,
                                       ucontext_t *uc, const uint8_t *ip);

static void sigill_handler(int sig, siginfo_t *si, void *vctx) {
    ucontext_t *uc=(ucontext_t*)vctx;
    const uint8_t *ip=(const uint8_t*)(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    if(emulate_popcnt(uc,ip) || emulate_crc32(uc,ip) || emulate_sse4(uc,ip)) return;
    log_unsupported(uc,ip);
    dispatch_downstream_sigill(sig, si, vctx, uc, ip);
}


typedef int (*real_sigaction_fn_t)(int, const struct sigaction *, struct sigaction *);
typedef sighandler_t (*real_signal_fn_t)(int, sighandler_t);
static real_sigaction_fn_t real_sigaction_fn = NULL;
static real_signal_fn_t real_signal_fn = NULL;
static int installing_sigill = 0;
static struct sigaction downstream_sigill;
static volatile sig_atomic_t downstream_valid = 0;
static volatile sig_atomic_t sigill_registration_logs = 0;

static real_sigaction_fn_t resolve_real_sigaction(void) {
    if (!real_sigaction_fn)
        real_sigaction_fn = (real_sigaction_fn_t)dlsym(RTLD_NEXT, "sigaction");
    return real_sigaction_fn;
}

static void build_sigill_action(struct sigaction *sa) {
    memset(sa, 0, sizeof(*sa));
    sa->sa_sigaction = sigill_handler;
    sigemptyset(&sa->sa_mask);
    sa->sa_flags = SA_SIGINFO | SA_ONSTACK;
}

static int force_sigill_handler(struct sigaction *oldact) {
    real_sigaction_fn_t fn = resolve_real_sigaction();
    if (!fn) { errno = ENOSYS; return -1; }
    struct sigaction sa;
    build_sigill_action(&sa);
    installing_sigill = 1;
    int rc = fn(SIGILL, &sa, oldact);
    installing_sigill = 0;
    return rc;
}

static void log_sigill_registration(const char *api) {
    sig_atomic_t n = sigill_registration_logs++;
    if (n >= 3) return;
    char b[224], *p=b, *e=b+sizeof(b)-1;
    p=append_str(p,e,"retro-sse v" RETRO_SSE_VERSION ": chained SIGILL handler via ");
    p=append_str(p,e,api);
    p=append_str(p,e," pid=");
    p=append_u64_dec(p,e,(uint64_t)getpid());
    p=append_str(p,e," comm=");
    p=append_str(p,e,proc_name);
    if(p<e)*p++='\n';
    log_raw(b,(size_t)(p-b));
}

static void log_chain_failure(ucontext_t *uc, const uint8_t *ip, const char *why) {
    char b[320], *p=b, *e=b+sizeof(b)-1;
    p=append_str(p,e,"retro-sse v" RETRO_SSE_VERSION ": downstream SIGILL ");
    p=append_str(p,e,why);
    p=append_str(p,e," pid=");
    p=append_u64_dec(p,e,(uint64_t)getpid());
    p=append_str(p,e," comm=");
    p=append_str(p,e,proc_name);
    p=append_str(p,e," rip=");
    p=append_u64_hex(p,e,(uint64_t)(uintptr_t)ip);
    p=append_str(p,e," rflags=");
    p=append_u64_hex(p,e,(uint64_t)uc->uc_mcontext.gregs[REG_EFL]);
    if(p<e)*p++='\n';
    log_raw(b,(size_t)(p-b));
}

static int install_downstream_action(const struct sigaction *act,
                                     struct sigaction *oldact,
                                     const char *api) {
    if (oldact) {
        if (downstream_valid) *oldact = downstream_sigill;
        else memset(oldact, 0, sizeof(*oldact));
    }
    if (act) {
        downstream_sigill = *act;
        downstream_valid = 1;
        log_sigill_registration(api);
    }
    /* Keep our emulator as the kernel-visible SIGILL action. */
    return force_sigill_handler(NULL);
}

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
    real_sigaction_fn_t fn = resolve_real_sigaction();
    if (!fn) { errno = ENOSYS; return -1; }
    if (signum != SIGILL || installing_sigill)
        return fn(signum, act, oldact);
    if (act == NULL) {
        if (oldact) {
            if (downstream_valid) *oldact = downstream_sigill;
            else memset(oldact, 0, sizeof(*oldact));
        }
        return 0;
    }
    return install_downstream_action(act, oldact, "sigaction");
}

int __sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
    return sigaction(signum, act, oldact);
}

int __libc_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
    return sigaction(signum, act, oldact);
}

sighandler_t signal(int signum, sighandler_t handler) {
    if (signum == SIGILL) {
        struct sigaction act, oldact;
        memset(&act, 0, sizeof(act));
        act.sa_handler = handler;
        sigemptyset(&act.sa_mask);
        act.sa_flags = SA_RESTART;
        if (install_downstream_action(&act, &oldact, "signal") != 0)
            return SIG_ERR;
        if (oldact.sa_flags & SA_SIGINFO)
            return SIG_DFL;
        return oldact.sa_handler;
    }
    if (!real_signal_fn)
        real_signal_fn = (real_signal_fn_t)dlsym(RTLD_NEXT, "signal");
    if (!real_signal_fn) { errno = ENOSYS; return SIG_ERR; }
    return real_signal_fn(signum, handler);
}

static void dispatch_downstream_sigill(int sig, siginfo_t *si, void *vctx,
                                       ucontext_t *uc, const uint8_t *ip) {
    if (!downstream_valid) {
        log_chain_failure(uc, ip, "missing; terminating");
        _exit(128 + SIGILL);
    }

    struct sigaction a = downstream_sigill;
    uintptr_t before = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];

    if (a.sa_handler == SIG_DFL) {
        log_chain_failure(uc, ip, "default; terminating");
        _exit(128 + SIGILL);
    }
    if (a.sa_handler == SIG_IGN) {
        log_chain_failure(uc, ip, "ignored but instruction cannot resume");
        _exit(128 + SIGILL);
    }

    if (a.sa_flags & SA_SIGINFO)
        a.sa_sigaction(sig, si, vctx);
    else
        a.sa_handler(sig);

    /* A downstream handler that returns without changing the faulting RIP
       would immediately fault again forever. Fail explicitly instead. */
    if ((uintptr_t)uc->uc_mcontext.gregs[REG_RIP] == before) {
        log_chain_failure(uc, ip, "returned without advancing RIP");
        _exit(128 + SIGILL);
    }
}

__attribute__((constructor))
static void retro_sse_init(void) {
    init_persistent_log();
    stack_t ss; memset(&ss,0,sizeof(ss)); ss.ss_sp=altstack_mem; ss.ss_size=sizeof(altstack_mem); (void)sigaltstack(&ss,NULL);
    if(force_sigill_handler(&old_sigill)==0){
        downstream_sigill = old_sigill;
        downstream_valid = 1;
        char b[160],*p=b,*e=b+sizeof(b)-1;
        p=append_str(p,e,"retro-sse v" RETRO_SSE_VERSION ": active pid=");p=append_u64_dec(p,e,(uint64_t)getpid());p=append_str(p,e," comm=");p=append_str(p,e,proc_name);if(p<e)*p++='\n';log_raw(b,(size_t)(p-b));
    }
}
