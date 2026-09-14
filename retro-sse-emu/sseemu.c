#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <ucontext.h>
#include <sys/ucontext.h>
#include <sys/syscall.h>

#if !defined(__x86_64__)
#error "retro-sse-emu currently supports x86_64 only"
#endif

typedef union {
    uint8_t  u8[16];
    uint16_t u16[8];
    uint32_t u32[4];
    uint64_t u64[2];
} xmm128_t;

static struct sigaction old_sigill;
static uint8_t altstack_mem[64 * 1024];

static void log_msg(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    ssize_t wr = write(STDERR_FILENO, s, n);
    (void)wr;
}

static void log_hex64(uint64_t v) {
    char b[19] = "0x0000000000000000";
    static const char h[] = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        b[17 - i] = h[v & 0xf];
        v >>= 4;
    }
    ssize_t wr = write(STDERR_FILENO, b, 18);
    (void)wr;
}

static void fatal_unsupported(ucontext_t *uc, const uint8_t *ip) {
    (void)uc;
    log_msg("retro-sse: unsupported SIGILL at ");
    log_hex64((uint64_t)(uintptr_t)ip);
    log_msg(" bytes=");
    static const char h[] = "0123456789abcdef";
    char out[3];
    for (int i = 0; i < 12; i++) {
        uint8_t x = ip[i];
        out[0] = h[x >> 4]; out[1] = h[x & 15]; out[2] = ' ';
        ssize_t wr = write(STDERR_FILENO, out, 3);
        (void)wr;
    }
    log_msg("\n");
    _exit(132);
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
};

static int parse_prefixes(struct dec *d, const uint8_t *ip) {
    memset(d, 0, sizeof(*d));
    d->start = ip;
    d->p = ip;
    int seen66 = 0;
    for (;;) {
        uint8_t b = *d->p;
        if (b == 0x66) { seen66 = 1; d->p++; continue; }
        if (b >= 0x40 && b <= 0x4f) { d->rex = b; d->p++; continue; }
        break;
    }
    return seen66 ? 0 : -1;
}

static int parse_modrm(struct dec *d) {
    d->modrm = *d->p++;
    d->mod = d->modrm >> 6;
    d->reg = ((d->modrm >> 3) & 7) | ((d->rex & 0x4) ? 8 : 0); /* REX.R */
    d->rm  = (d->modrm & 7) | ((d->rex & 0x1) ? 8 : 0);         /* REX.B */
    return 0;
}

static uintptr_t calc_ea(ucontext_t *uc, struct dec *d, int *ok) {
    *ok = 0;
    if (d->mod == 3) return 0;

    unsigned rm_lo = d->modrm & 7;
    uintptr_t base = 0, index = 0;
    int32_t disp = 0;

    if (rm_lo == 4) { /* SIB */
        uint8_t sib = *d->p++;
        unsigned scale = sib >> 6;
        unsigned idx_lo = (sib >> 3) & 7;
        unsigned base_lo = sib & 7;
        unsigned idx = idx_lo | ((d->rex & 0x2) ? 8 : 0);  /* REX.X */
        unsigned bas = base_lo | ((d->rex & 0x1) ? 8 : 0); /* REX.B */

        if (!(idx_lo == 4 && !(d->rex & 0x2))) {
            greg_t *g = gpr_slot(uc, idx);
            if (!g) return 0;
            index = ((uintptr_t)*g) << scale;
        }

        if (d->mod == 0 && base_lo == 5) {
            memcpy(&disp, d->p, 4); d->p += 4;
            base = 0;
        } else {
            greg_t *g = gpr_slot(uc, bas);
            if (!g) return 0;
            base = (uintptr_t)*g;
        }
    } else if (d->mod == 0 && rm_lo == 5) { /* RIP-relative */
        memcpy(&disp, d->p, 4); d->p += 4;
        base = (uintptr_t)d->p;
    } else {
        greg_t *g = gpr_slot(uc, d->rm);
        if (!g) return 0;
        base = (uintptr_t)*g;
    }

    if (d->mod == 1) {
        int8_t x = *(const int8_t *)d->p; d->p++;
        disp += x;
    } else if (d->mod == 2) {
        int32_t x; memcpy(&x, d->p, 4); d->p += 4;
        disp += x;
    }

    *ok = 1;
    return base + index + (intptr_t)disp;
}

static uint8_t read_rm8(ucontext_t *uc, struct dec *d, int *ok) {
    if (d->mod != 3) {
        uintptr_t ea = calc_ea(uc, d, ok);
        if (!*ok) return 0;
        return *(volatile uint8_t *)ea;
    }
    unsigned rm_lo = d->modrm & 7;
    greg_t *g = gpr_slot(uc, d->rm);
    if (!g) { *ok = 0; return 0; }
    *ok = 1;
    uint64_t v = (uint64_t)*g;
    if (!d->rex && rm_lo >= 4 && rm_lo <= 7) {
        /* AH, CH, DH, BH map to RAX,RCX,RDX,RBX high byte. */
        static const unsigned hi_map[4] = {0,1,2,3};
        greg_t *hg = gpr_slot(uc, hi_map[rm_lo - 4]);
        return (uint8_t)(((uint64_t)*hg >> 8) & 0xff);
    }
    return (uint8_t)(v & 0xff);
}

static uint32_t read_rm32(ucontext_t *uc, struct dec *d, int *ok) {
    if (d->mod != 3) {
        uintptr_t ea = calc_ea(uc, d, ok);
        if (!*ok) return 0;
        uint32_t v; memcpy(&v, (void *)ea, 4); return v;
    }
    greg_t *g = gpr_slot(uc, d->rm);
    if (!g) { *ok = 0; return 0; }
    *ok = 1;
    return (uint32_t)*g;
}

static uint64_t read_rm64(ucontext_t *uc, struct dec *d, int *ok) {
    if (d->mod != 3) {
        uintptr_t ea = calc_ea(uc, d, ok);
        if (!*ok) return 0;
        uint64_t v; memcpy(&v, (void *)ea, 8); return v;
    }
    greg_t *g = gpr_slot(uc, d->rm);
    if (!g) { *ok = 0; return 0; }
    *ok = 1;
    return (uint64_t)*g;
}

static int read_rm128(ucontext_t *uc, struct dec *d, xmm128_t *out) {
    if (d->mod == 3) return load_xmm(uc, d->rm, out);
    int ok = 0;
    uintptr_t ea = calc_ea(uc, d, &ok);
    if (!ok) return -1;
    memcpy(out, (void *)ea, 16);
    return 0;
}

static int write_rm32(ucontext_t *uc, struct dec *d, uint32_t v) {
    if (d->mod != 3) {
        int ok = 0; uintptr_t ea = calc_ea(uc, d, &ok); if (!ok) return -1;
        memcpy((void *)ea, &v, 4); return 0;
    }
    greg_t *g = gpr_slot(uc, d->rm); if (!g) return -1;
    *g = (greg_t)(uint64_t)v; /* x86-64 32-bit GPR write zero-extends */
    return 0;
}

static int write_rm64(ucontext_t *uc, struct dec *d, uint64_t v) {
    if (d->mod != 3) {
        int ok = 0; uintptr_t ea = calc_ea(uc, d, &ok); if (!ok) return -1;
        memcpy((void *)ea, &v, 8); return 0;
    }
    greg_t *g = gpr_slot(uc, d->rm); if (!g) return -1;
    *g = (greg_t)v;
    return 0;
}

static void set_rip(ucontext_t *uc, const uint8_t *p) {
    uc->uc_mcontext.gregs[REG_RIP] = (greg_t)(uintptr_t)p;
}

static int emulate_sse41(ucontext_t *uc, const uint8_t *ip) {
    struct dec d;
    if (parse_prefixes(&d, ip) < 0) return 0;
    if (*d.p++ != 0x0f) return 0;
    uint8_t map = *d.p++;

    if (map == 0x3a) {
        uint8_t op = *d.p++;
        if (!(op == 0x20 || op == 0x22 || op == 0x14 || op == 0x16)) return 0;
        parse_modrm(&d);
        const uint8_t *modrm_end_before_ea = d.p;
        (void)modrm_end_before_ea;

        if (op == 0x20) { /* PINSRB xmm, r/m8, imm8 */
            int ok = 0;
            uint8_t src = read_rm8(uc, &d, &ok); if (!ok) return 0;
            uint8_t imm = *d.p++;
            xmm128_t x; if (load_xmm(uc, d.reg, &x)) return 0;
            x.u8[imm & 15] = src;
            if (store_xmm(uc, d.reg, &x)) return 0;
            set_rip(uc, d.p);
            return 1;
        }
        if (op == 0x22) { /* PINSRD / PINSRQ */
            int ok = 0;
            xmm128_t x; if (load_xmm(uc, d.reg, &x)) return 0;
            if (d.rex & 0x08) {
                uint64_t src = read_rm64(uc, &d, &ok); if (!ok) return 0;
                uint8_t imm = *d.p++;
                x.u64[imm & 1] = src;
            } else {
                uint32_t src = read_rm32(uc, &d, &ok); if (!ok) return 0;
                uint8_t imm = *d.p++;
                x.u32[imm & 3] = src;
            }
            if (store_xmm(uc, d.reg, &x)) return 0;
            set_rip(uc, d.p);
            return 1;
        }
        if (op == 0x14) { /* PEXTRB r32/m8, xmm, imm8 */
            uint8_t imm;
            xmm128_t x; if (load_xmm(uc, d.reg, &x)) return 0;
            if (d.mod == 3) {
                imm = *d.p++;
                greg_t *g = gpr_slot(uc, d.rm); if (!g) return 0;
                *g = (greg_t)(uint64_t)x.u8[imm & 15]; /* register form zero-extends */
            } else {
                int ok = 0; uintptr_t ea = calc_ea(uc, &d, &ok); if (!ok) return 0;
                imm = *d.p++;
                *(volatile uint8_t *)ea = x.u8[imm & 15];
            }
            set_rip(uc, d.p); return 1;
        }
        if (op == 0x16) { /* PEXTRD / PEXTRQ */
            uint8_t imm;
            xmm128_t x; if (load_xmm(uc, d.reg, &x)) return 0;
            if (d.mod == 3) {
                imm = *d.p++;
                if (d.rex & 0x08) {
                    if (write_rm64(uc, &d, x.u64[imm & 1])) return 0;
                } else {
                    if (write_rm32(uc, &d, x.u32[imm & 3])) return 0;
                }
            } else {
                int ok = 0; uintptr_t ea = calc_ea(uc, &d, &ok); if (!ok) return 0;
                imm = *d.p++;
                if (d.rex & 0x08) { uint64_t v = x.u64[imm & 1]; memcpy((void *)ea, &v, 8); }
                else { uint32_t v = x.u32[imm & 3]; memcpy((void *)ea, &v, 4); }
            }
            set_rip(uc, d.p); return 1;
        }
    }

    if (map == 0x38) {
        uint8_t op = *d.p++;
        if (!(op == 0x3b || op == 0x17 || op == 0x40)) return 0;
        parse_modrm(&d);
        xmm128_t dst, src;
        if (load_xmm(uc, d.reg, &dst)) return 0;
        if (read_rm128(uc, &d, &src)) return 0;

        if (op == 0x3b) { /* PMINUD */
            for (int i = 0; i < 4; i++) if (src.u32[i] < dst.u32[i]) dst.u32[i] = src.u32[i];
            if (store_xmm(uc, d.reg, &dst)) return 0;
            set_rip(uc, d.p); return 1;
        }
        if (op == 0x40) { /* PMULLD */
            for (int i = 0; i < 4; i++) dst.u32[i] = (uint32_t)((uint64_t)dst.u32[i] * (uint64_t)src.u32[i]);
            if (store_xmm(uc, d.reg, &dst)) return 0;
            set_rip(uc, d.p); return 1;
        }
        if (op == 0x17) { /* PTEST */
            uint64_t a0 = dst.u64[0] & src.u64[0];
            uint64_t a1 = dst.u64[1] & src.u64[1];
            uint64_t b0 = (~dst.u64[0]) & src.u64[0];
            uint64_t b1 = (~dst.u64[1]) & src.u64[1];
            greg_t *ef = &uc->uc_mcontext.gregs[REG_EFL];
            uint64_t flags = (uint64_t)*ef;
            const uint64_t CF = 1u << 0, PF = 1u << 2, AF = 1u << 4, ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;
            flags &= ~(CF|PF|AF|ZF|SF|OF);
            if ((a0 | a1) == 0) flags |= ZF;
            if ((b0 | b1) == 0) flags |= CF;
            *ef = (greg_t)flags;
            set_rip(uc, d.p); return 1;
        }
    }

    return 0;
}

static void sigill_handler(int sig, siginfo_t *si, void *vctx) {
    (void)sig; (void)si;
    ucontext_t *uc = (ucontext_t *)vctx;
    const uint8_t *ip = (const uint8_t *)(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    if (emulate_sse41(uc, ip)) return;
    fatal_unsupported(uc, ip);
}

__attribute__((constructor))
static void retro_sse_init(void) {
    stack_t ss;
    memset(&ss, 0, sizeof(ss));
    ss.ss_sp = altstack_mem;
    ss.ss_size = sizeof(altstack_mem);
    (void)sigaltstack(&ss, NULL);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigill_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    if (sigaction(SIGILL, &sa, &old_sigill) == 0)
        log_msg("retro-sse: SIGILL compatibility layer active\n");
}

