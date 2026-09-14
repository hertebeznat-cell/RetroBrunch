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

#if !defined(__x86_64__)
#error "retro-sse-emu currently supports x86_64 only"
#endif

#define RETRO_SSE_VERSION "0.2"

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

static int emulate_sse4(ucontext_t *uc, const uint8_t *ip) {
    struct dec d; parse_prefixes(&d,ip);
    if(!d.p66 || *d.p++!=0x0f) return 0;
    uint8_t map=*d.p++;

    if(map==0x3a){
        uint8_t op=*d.p++;
        if(!(op==0x20||op==0x22||op==0x14||op==0x16||op==0x0c||op==0x0d||op==0x0e)) return 0;
        parse_modrm(&d);
        if(op==0x20){int ok=0;uint8_t src=read_rm8(uc,&d,&ok);if(!ok)return 0;uint8_t imm=*d.p++;xmm128_t x;if(load_xmm(uc,d.reg,&x))return 0;x.u8[imm&15]=src;if(store_xmm(uc,d.reg,&x))return 0;set_rip(uc,d.p);return 1;}
        if(op==0x22){int ok=0;xmm128_t x;if(load_xmm(uc,d.reg,&x))return 0;if(d.rex&8){uint64_t src=read_rm64(uc,&d,&ok);if(!ok)return 0;uint8_t imm=*d.p++;x.u64[imm&1]=src;}else{uint32_t src=read_rm32(uc,&d,&ok);if(!ok)return 0;uint8_t imm=*d.p++;x.u32[imm&3]=src;}if(store_xmm(uc,d.reg,&x))return 0;set_rip(uc,d.p);return 1;}
        if(op==0x14){uint8_t imm;xmm128_t x;if(load_xmm(uc,d.reg,&x))return 0;if(d.mod==3){imm=*d.p++;greg_t*g=gpr_slot(uc,d.rm);if(!g)return 0;*g=(greg_t)(uint64_t)x.u8[imm&15];}else{int ok=0;uintptr_t ea=calc_ea(uc,&d,&ok);if(!ok)return 0;imm=*d.p++;*(volatile uint8_t*)ea=x.u8[imm&15];}set_rip(uc,d.p);return 1;}
        if(op==0x16){uint8_t imm;xmm128_t x;if(load_xmm(uc,d.reg,&x))return 0;if(d.mod==3){imm=*d.p++;if(d.rex&8){if(write_rm64(uc,&d,x.u64[imm&1]))return 0;}else{if(write_rm32(uc,&d,x.u32[imm&3]))return 0;}}else{int ok=0;uintptr_t ea=calc_ea(uc,&d,&ok);if(!ok)return 0;imm=*d.p++;if(d.rex&8){uint64_t v=x.u64[imm&1];memcpy((void*)ea,&v,8);}else{uint32_t v=x.u32[imm&3];memcpy((void*)ea,&v,4);}}set_rip(uc,d.p);return 1;}
        if(op==0x0c||op==0x0d||op==0x0e){xmm128_t dst,src;if(load_xmm(uc,d.reg,&dst)||read_rm128(uc,&d,&src))return 0;uint8_t imm=*d.p++;if(op==0x0c){for(int i=0;i<4;i++)if(imm&(1u<<i))dst.u32[i]=src.u32[i];}else if(op==0x0d){for(int i=0;i<2;i++)if(imm&(1u<<i))dst.u64[i]=src.u64[i];}else{for(int i=0;i<8;i++)if(imm&(1u<<i))dst.u16[i]=src.u16[i];}if(store_xmm(uc,d.reg,&dst))return 0;set_rip(uc,d.p);return 1;}
    }

    if(map==0x38){
        uint8_t op=*d.p++;
        parse_modrm(&d); xmm128_t dst,src;
        if(load_xmm(uc,d.reg,&dst)||read_rm128(uc,&d,&src)) return 0;
        switch(op){
            case 0x17:{uint64_t a=(dst.u64[0]&src.u64[0])|(dst.u64[1]&src.u64[1]);uint64_t b=((~dst.u64[0])&src.u64[0])|((~dst.u64[1])&src.u64[1]);greg_t*ef=&uc->uc_mcontext.gregs[REG_EFL];uint64_t f=(uint64_t)*ef;const uint64_t M=(1u<<0)|(1u<<2)|(1u<<4)|(1u<<6)|(1u<<7)|(1u<<11);f&=~M;if(!a)f|=1u<<6;if(!b)f|=1u<<0;*ef=(greg_t)f;break;}
            case 0x28: for(int i=0;i<2;i++) dst.i64[i]=(int64_t)dst.i32[i*2]*(int64_t)src.i32[i*2]; break;
            case 0x29: for(int i=0;i<2;i++) dst.u64[i]=(dst.u64[i]==src.u64[i])?UINT64_MAX:0; break;
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
            default: return 0;
        }
        if(op!=0x17 && store_xmm(uc,d.reg,&dst)) return 0;
        set_rip(uc,d.p); return 1;
    }
    return 0;
}

static void sigill_handler(int sig, siginfo_t *si, void *vctx) {
    (void)sig; (void)si;
    ucontext_t *uc=(ucontext_t*)vctx;
    const uint8_t *ip=(const uint8_t*)(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    if(emulate_popcnt(uc,ip) || emulate_crc32(uc,ip) || emulate_sse4(uc,ip)) return;
    log_unsupported(uc,ip);
    _exit(132);
}

__attribute__((constructor))
static void retro_sse_init(void) {
    init_persistent_log();
    stack_t ss; memset(&ss,0,sizeof(ss)); ss.ss_sp=altstack_mem; ss.ss_size=sizeof(altstack_mem); (void)sigaltstack(&ss,NULL);
    struct sigaction sa; memset(&sa,0,sizeof(sa)); sa.sa_sigaction=sigill_handler; sigemptyset(&sa.sa_mask); sa.sa_flags=SA_SIGINFO|SA_ONSTACK;
    if(sigaction(SIGILL,&sa,&old_sigill)==0){
        char b[160],*p=b,*e=b+sizeof(b)-1;
        p=append_str(p,e,"retro-sse v" RETRO_SSE_VERSION ": active pid=");p=append_u64_dec(p,e,(uint64_t)getpid());p=append_str(p,e," comm=");p=append_str(p,e,proc_name);if(p<e)*p++='\n';log_raw(b,(size_t)(p-b));
    }
}
