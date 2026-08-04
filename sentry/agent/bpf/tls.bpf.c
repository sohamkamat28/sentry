// SENTRY kernel sensor.
//
// uprobes on the TLS library entry/exit points capture request data at the exact
// moment it is plaintext in process memory. The TLS chain is never broken, no
// certificate is distributed, and the application is not modified.
//
// Two properties this file is responsible for:
//
//   1. Two-stage in-kernel filtering. Approver maps reject anything outside the
//      watched cgroups and ports; an LRU discarder map drops known-noise
//      signatures. Both run before any data is copied to the ring buffer, which
//      is what makes the CPU cost claim true rather than aspirational.
//
//   2. Data-class tagging without retention. Payloads are matched against
//      identifier patterns in a per-CPU scratch buffer and discarded in the same
//      operation. The event carries a bitmask; there is no field anywhere in
//      this program, the wire format, or the database capable of holding a
//      matched value.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

/* BPF_UPROBE / BPF_URETPROBE are aliases for the kprobe macros: a uprobe
 * receives the same pt_regs argument frame. Older libbpf headers, including the
 * copy vendored from cilium/ebpf, define only the kprobe spellings. */
/* bpf_loop is helper 181. The libbpf copy vendored from cilium/ebpf predates
 * it, so it is declared here rather than upgrading the whole header set. */
#ifndef bpf_loop
static long (*bpf_loop)(__u32 nr_loops, void *callback_fn, void *callback_ctx,
                        __u64 flags) = (void *)181;
#endif

#ifndef BPF_UPROBE
#define BPF_UPROBE(name, args...)    BPF_KPROBE(name, ##args)
#endif
#ifndef BPF_URETPROBE
#define BPF_URETPROBE(name, args...) BPF_KRETPROBE(name, ##args)
#endif

/* Copy window: enough for a request line plus headers. Bodies are scanned for
 * data classes but never copied out. */
#define SCAN_BYTES     512
/* Classification window. Kept separate from the copy window and deliberately
 * small: the verifier must be able to walk every path, and an unrolled scan over
 * kilobytes exceeds the branch range long before it exceeds the instruction
 * limit. */
#define CLASSIFY_BYTES 256
#define MAX_HEADERS    32
#define METHOD_MAX     8

/* Field-name window.
 *
 * The *names* of the keys in a JSON body, NUL-separated. Names are schema, not
 * content: `accountNumber` describes the shape of a response and carries none
 * of the account number. The value never leaves the kernel — it is not copied,
 * not hashed, not counted — and the rewind in extract_fields_step is what
 * guarantees it, because a token that turns out to be a value is unwound out of
 * the buffer before the next byte is read.
 *
 * This exists because stage 12's fingerprint is specified to key on response
 * schema and had no schema to key on: the classifier extracted data classes and
 * discarded everything else, so the resurrection case scored 0.80 against its
 * own 0.85 threshold on behavioural features alone.
 *
 * Both sizes are powers of two so the verifier accepts a masked index. */
#define FIELDS_BYTES   128
#define FIELDS_MASK    (FIELDS_BYTES - 1)

#define DIR_INGRESS 1
#define DIR_EGRESS  2

#define STAT_CAPTURED           0
#define STAT_FILTERED_APPROVER  1
#define STAT_FILTERED_DISCARDER 2
#define STAT_EMITTED            3
#define STAT_FILTERED_CGROUP    4
#define STAT_CONTINUATION       5

// Data classes, bit positions. Mirrors sentry.v1.DataClass.
#define DC_PAN        (1 << 0)
#define DC_AADHAAR    (1 << 1)
#define DC_IFSC       (1 << 2)
#define DC_ACCOUNT_NO (1 << 3)
#define DC_CARD       (1 << 4)
#define DC_CVV        (1 << 5)
#define DC_DOB        (1 << 6)

struct ssl_args {
    __u64 ssl_ptr;   /* the connection identity, used to join body to header */
    __u64 buf_ptr;
    __u32 num;
    __u32 fd;
    /* Where SSL_write_ex/SSL_read_ex will put the byte count.
     *
     * The _ex forms return 1 for success rather than a length, so the return
     * probe has to read the count out of the caller's own memory. Zero for the
     * classic entry points, whose return value is the length. */
    __u64 count_ptr;
};

struct sock_tuple {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct event {
    __u64 wall_ns;
    __u32 pid;
    __u64 cgroup_id;
    __u32 data_len;
    __u16 dport;
    __u32 daddr;
    __u8  direction;
    __u8  data_classes;
    __u8  is_request;
    __u8  is_continuation;   /* a body write joined to a preceding header */
    __u8  fields_len;        /* bytes of `fields` that are real */
    __u64 conn_key;
    char  data[SCAN_BYTES];
    char  fields[FIELDS_BYTES];
};

// entry -> exit correlation. SSL_read cannot be read at entry: the buffer is
// empty until the call returns, so both directions stash arguments here and the
// return probe reads the payload.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct ssl_args);
} active_ssl SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, __u8);
} approver_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u8);
} approver_cgroups SEC(".maps");

// LRU so a signature that stops appearing ages out on its own: a bad discarder
// cannot permanently blind the sensor.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u64);
} discarders SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct sock_tuple);
} sock_info SEC(".maps");

/* Connections with a header emitted and a body possibly still to come.
 *
 * HTTP framing does not respect SSL_write boundaries: a server routinely writes
 * headers and body as separate calls. Without this, the body buffer matches
 * neither a request line nor a status line and is dropped in kernel — which is
 * where every response body was going, taking the data-class scan with it.
 *
 * LRU, so a connection that goes away is reclaimed without bookkeeping.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);      /* ssl_ptr */
    __type(value, __u64);    /* ktime the header was seen */
} pending_msg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 6);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

/* Runtime settings, written by the agent at startup.
 *
 * [0] cgroup filtering enabled
 * [1] last cgroup id observed — diagnostic, so an operator scoping by cgroup can
 *     read the value this kernel actually reports instead of guessing at it
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} settings SEC(".maps");

#define SET_CGROUP_FILTER 0
#define SET_LAST_CGROUP   1

static __always_inline __u64 setting(__u32 key) {
    __u64 *v = bpf_map_lookup_elem(&settings, &key);
    return v ? *v : 0;
}

// Per-CPU scratch. Overwritten by the next event; never persisted anywhere.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event);
} scratch SEC(".maps");

static __always_inline void bump(__u32 key) {
    __u64 *v = bpf_map_lookup_elem(&stats, &key);
    if (v) __sync_fetch_and_add(v, 1);
}

static __always_inline int is_digit(char c) { return c >= '0' && c <= '9'; }
static __always_inline int is_upper(char c) { return c >= 'A' && c <= 'Z'; }

// ── data-class detection ────────────────────────────────────────────────────
/* Data-class scan.
 *
 * This runs under bpf_loop() rather than as an in-line loop, and that is not a
 * style choice. A rolled 256-iteration loop with branches in its body forced the
 * verifier to walk every path: the program was only 625 instructions but the
 * verifier processed 1,000,001 of them and rejected it at its limit of
 * 1,000,000. bpf_loop moves iteration into the kernel at runtime, so the
 * callback body is verified exactly once regardless of the iteration count.
 *
 * Indices are masked rather than compared, which gives the verifier a provable
 * bound on every buffer access without a branch.
 */
struct classify_ctx {
    char *buf;
    __u32 len;
    __u32 mask;
    __u32 digit_run;
    __u32 run_start;
    __u32 alpha_run;
    __u32 prev_alpha;   /* letter run immediately before the current digit run */
};

/* Counters are clamped, and that is load-bearing rather than defensive.
 *
 * Left unbounded, the verifier tracks each counter's concrete value and forks a
 * state per increment — the log shows it walking alpha_run=15, 16, 17 and so on.
 * With the second rejection it was still processing 1,000,001 instructions
 * inside the callback for that reason alone. Clamping keeps each scalar in a
 * range small enough that the state space stays flat, and nothing is lost: the
 * only comparisons that matter are against 4, 5, 12 and the 9-19 band.
 */
#define MAX_DIGIT_RUN 20
#define MAX_ALPHA_RUN 8

/* Masks wide enough to hold the clamped values above and no wider. Applied on
 * every load and every store, for the reason spelled out in classify_step. */
#define DIGIT_RUN_MASK 31
#define ALPHA_RUN_MASK 15
#define CLASS_MASK     0xff

static long classify_step(__u32 i, void *raw) {
    struct classify_ctx *c = raw;
    if (i >= c->len) return 1;              /* break */

    __u32 idx = i & (CLASSIFY_BYTES - 1);
    char ch = c->buf[idx];

    /* Load into locals, mask, operate, store back.
     *
     * A bpf_loop callback is verified once, and the context it is handed is
     * opaque memory across iterations: however tightly a counter was clamped
     * before it was stored, the value read back is an unbounded 32-bit scalar
     * as far as the verifier is concerned. Three unbounded counters feeding a
     * branch tree is a state space large enough to walk past the million
     * instruction ceiling — and whether it actually does depends on how the
     * compiler laid the branches out. clang 22 produced an object this kernel
     * accepted; clang 19, on the same source, produced one it rejected at
     * exactly 1,000,001 instructions.
     *
     * Masking on load is one instruction and restores the bound the clamp
     * already guarantees, so the verifier sees 0-31 and 0-15 instead of 0-2^32.
     * That makes acceptance a property of the program rather than of the
     * toolchain that happened to build it.
     */
    __u32 digit_run  = c->digit_run  & DIGIT_RUN_MASK;
    __u32 alpha_run  = c->alpha_run  & ALPHA_RUN_MASK;
    __u32 prev_alpha = c->prev_alpha & ALPHA_RUN_MASK;
    __u32 mask       = c->mask       & CLASS_MASK;

    if (is_digit(ch)) {
        /* Snapshot the letter run as the digit run opens.
         *
         * alpha_run is cleared on the first digit, so testing it against a
         * digit_run of four — which is what PAN requires — always saw zero and
         * the class was never detected. IFSC happened to survive only because it
         * closes on the first digit, before the reset mattered. */
        if (digit_run == 0) prev_alpha = alpha_run;
        if (digit_run < MAX_DIGIT_RUN) digit_run++;

        /* PAN closes as five letters then four digits; IFSC as four letters then
         * a literal zero. Both decided from state already carried, so no
         * lookahead and no second buffer read. */
        if (prev_alpha == 5 && digit_run == 4) mask |= DC_PAN;
        if (prev_alpha == 4 && digit_run == 1 && ch == '0') mask |= DC_IFSC;

        alpha_run = 0;
    } else {
        if (is_upper(ch)) {
            if (alpha_run < MAX_ALPHA_RUN) alpha_run++;
        } else {
            alpha_run = 0;
        }

        if (digit_run > 0) {
            /* Checksums are verified in userspace against the same window that
             * is copied out. Verhoeff and Luhn tables cost more verifier budget
             * here than they are worth, and the run length is already a strong
             * signal. */
            if (digit_run == 12) mask |= DC_AADHAAR;
            if (digit_run >= 13) mask |= DC_CARD;
            if (digit_run >= 9 && digit_run <= 18) mask |= DC_ACCOUNT_NO;
            digit_run = 0;
        }
    }

    c->digit_run  = digit_run  & DIGIT_RUN_MASK;
    c->alpha_run  = alpha_run  & ALPHA_RUN_MASK;
    c->prev_alpha = prev_alpha & ALPHA_RUN_MASK;
    c->mask       = mask       & CLASS_MASK;
    return 0;
}

static __always_inline __u8 classify(char *buf, __u32 len) {
    struct classify_ctx c = {};
    c.buf = buf;
    c.len = len > CLASSIFY_BYTES ? CLASSIFY_BYTES : len;

    bpf_loop(CLASSIFY_BYTES, classify_step, &c, 0);

    /* A run reaching the end of the window never hits the closing branch. */
    if (c.digit_run == 12) c.mask |= DC_AADHAAR;
    if (c.digit_run >= 13) c.mask |= DC_CARD;
    if (c.digit_run >= 9 && c.digit_run <= 18) c.mask |= DC_ACCOUNT_NO;

    return (__u8)c.mask;
}

// ── JSON field names ────────────────────────────────────────────────────────
/* Key names out of a JSON body, values left behind.
 *
 * A single forward pass, no lookahead. A quoted token is written into the output
 * as it is read, and its start position is remembered; when the token closes,
 * the next significant byte decides what it was. A `:` commits it — it was a
 * key — and anything else rewinds the write cursor back over it, because it was
 * a value and a value must not survive this function.
 *
 * That rewind is the privacy property, expressed as control flow rather than as
 * a promise. There is no path on which a value is still in the buffer when the
 * next token begins.
 *
 * Separate from classify_step and deliberately so. classify_step carries three
 * counters into a branch tree that clang 19 laid out at 1,000,001 instructions —
 * one past this kernel's ceiling — and folding a second state machine into it
 * would decide the whole program's acceptance on the compiler's mood. Two loops
 * are two budgets.
 */
struct fields_ctx {
    char *buf;
    __u32 len;
    __u32 outpos;      /* write cursor, 0..FIELDS_BYTES-1 */
    __u32 tok_start;   /* where the open token began, for the rewind */
    __u32 in_str;      /* inside a quoted token */
    __u32 pending;     /* a token closed and is awaiting its verdict */
    char out[FIELDS_BYTES];
};

static long extract_fields_step(__u32 i, void *raw) {
    struct fields_ctx *c = raw;
    if (i >= c->len) return 1;

    char ch = c->buf[i & (CLASSIFY_BYTES - 1)];

    /* Masked on load and on store, for the reason classify_step documents: the
     * verifier reads these back as unbounded scalars however tightly they were
     * clamped when written. */
    __u32 outpos    = c->outpos    & FIELDS_MASK;
    __u32 tok_start = c->tok_start & FIELDS_MASK;
    __u32 in_str    = c->in_str    & 1;
    __u32 pending   = c->pending   & 1;

    if (ch == '"') {
        if (in_str) {
            in_str = 0;
            pending = 1;          /* key or value — the next byte decides */
        } else {
            in_str = 1;
            pending = 0;
            tok_start = outpos;   /* the rewind point */
        }
    } else if (in_str) {
        /* Copy the token through as it is read. Committed by a `:`, unwound by
         * anything else. */
        c->out[outpos] = ch;
        outpos = (outpos + 1) & FIELDS_MASK;
    } else if (pending) {
        if (ch == ':') {
            c->out[outpos] = '\0';           /* commit: names are NUL-separated */
            outpos = (outpos + 1) & FIELDS_MASK;
        } else if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t') {
            outpos = tok_start;              /* rewind: that was a value */
        }
        if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t') pending = 0;
    }

    c->outpos    = outpos    & FIELDS_MASK;
    c->tok_start = tok_start & FIELDS_MASK;
    c->in_str    = in_str    & 1;
    c->pending   = pending   & 1;
    return 0;
}

/* Fills `dst` with NUL-separated key names and returns how many bytes are real.
 *
 * Also sets the two classes that cannot be recognised by value shape. A CVV is
 * three digits and a date of birth is a date; both match far too much ordinary
 * content — prices, counts, quantities, any timestamp — to be detected by what
 * they look like. DC_CVV and DC_DOB were defined in this file from the start and
 * nothing ever set either, so both were dead constants and `DataClass.CVV` sat
 * in the sensitive set unreachable. The key name is the only reliable signal,
 * and this is the pass that has it. */
static __always_inline __u8 extract_fields(char *buf, __u32 len, char *dst, __u8 *mask) {
    struct fields_ctx c = {};
    c.buf = buf;
    c.len = len > CLASSIFY_BYTES ? CLASSIFY_BYTES : len;

    bpf_loop(CLASSIFY_BYTES, extract_fields_step, &c, 0);

    /* An unterminated token is not a key. */
    __u32 n = (c.in_str || c.pending) ? (c.tok_start & FIELDS_MASK)
                                      : (c.outpos & FIELDS_MASK);

    __builtin_memcpy(dst, c.out, FIELDS_BYTES);

    for (__u32 j = 0; j < FIELDS_BYTES - 3; j++) {
        __u32 k = j & FIELDS_MASK;
        char a = c.out[k], b = c.out[(k + 1) & FIELDS_MASK];
        char d = c.out[(k + 2) & FIELDS_MASK];
        if ((a == 'c' || a == 'C') && (b == 'v' || b == 'V') && (d == 'v' || d == 'V'))
            *mask |= DC_CVV;
        if ((a == 'd' || a == 'D') && (b == 'o' || b == 'O') && (d == 'b' || d == 'B'))
            *mask |= DC_DOB;
    }

    return (__u8)(n > FIELDS_BYTES ? FIELDS_BYTES : n);
}

// ── HTTP inference ──────────────────────────────────────────────────────────
static __always_inline int looks_like_request(const char *b, __u32 len) {
    if (len < 5) return 0;
    if (b[0] == 'G' && b[1] == 'E' && b[2] == 'T') return 1;
    if (b[0] == 'P' && b[1] == 'O' && b[2] == 'S' && b[3] == 'T') return 1;
    if (b[0] == 'P' && b[1] == 'U' && b[2] == 'T') return 1;
    if (b[0] == 'D' && b[1] == 'E' && b[2] == 'L') return 1;
    if (b[0] == 'P' && b[1] == 'A' && b[2] == 'T') return 1;
    if (b[0] == 'H' && b[1] == 'E' && b[2] == 'A' && b[3] == 'D') return 1;
    if (b[0] == 'O' && b[1] == 'P' && b[2] == 'T') return 1;
    return 0;
}

static __always_inline int looks_like_response(const char *b, __u32 len) {
    return len >= 12 && b[0] == 'H' && b[1] == 'T' && b[2] == 'T' && b[3] == 'P';
}

static __always_inline __u64 signature(__u64 cgid, __u16 dport, const char *b) {
    __u64 h = cgid * 1099511628211ULL;
    h ^= (__u64)dport << 32;
    #pragma unroll
    for (int i = 0; i < 16; i++) { h ^= (__u64)b[i]; h *= 1099511628211ULL; }
    return h;
}

// Stage 1 approvers then stage 2 discarders, both before any copy.
static __always_inline int should_emit(__u64 cgid, __u16 dport, __u64 sig) {
    /* Record what this kernel actually reports, always. The id encoding for
     * cgroups is not stable across kernel versions, and a filter configured
     * against the wrong encoding drops one hundred percent of traffic while
     * looking healthy. Exposing the observed value makes that configurable
     * rather than a guess.
     */
    __u32 last_key = SET_LAST_CGROUP;
    bpf_map_update_elem(&settings, &last_key, &cgid, BPF_ANY);

    /* Cgroup scoping is opt-in. Off by default, because the port approver does
     * the real narrowing and a misconfigured cgroup filter fails silently and
     * totally — the worst failure mode available to a sensor. */
    if (setting(SET_CGROUP_FILTER) &&
        !bpf_map_lookup_elem(&approver_cgroups, &cgid)) {
        bump(STAT_FILTERED_CGROUP);
        return 0;
    }
    /* A port of zero means the socket tuple was never resolved — the kprobe
     * has not seen this connection, which is normal for the accept side. The
     * event is allowed through rather than dropped: silently discarding
     * everything that cannot be attributed is precisely the undercount this
     * sensor is supposed to make impossible. Userspace still sees port 0 and
     * can decide. */
    if (dport != 0 && !bpf_map_lookup_elem(&approver_ports, &dport)) {
        bump(STAT_FILTERED_APPROVER);
        return 0;
    }
    if (bpf_map_lookup_elem(&discarders, &sig)) {
        bump(STAT_FILTERED_DISCARDER);
        return 0;
    }
    return 1;
}

static __always_inline int handle_plaintext(struct ssl_args *a, int ret, __u8 dir) {
    __u32 zero = 0;
    struct event *e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e) return 0;

    /* Bounding the read length for the verifier.
     *
     * A clamp alone is not enough, and neither is a clamp plus a mask: the
     * compiler keeps a copy of the pre-clamp value in another register and uses
     * that at the call site, so the verifier still sees an unbounded scalar and
     * refuses with "R2 unbounded memory access". The asm barrier forces the
     * clamped value to be materialised before it is used, which is the standard
     * idiom for this and the only version of the three that loads.
     */
    __u32 len = (__u32)ret;
    if (len > SCAN_BYTES) len = SCAN_BYTES;
    asm volatile("" : "+r"(len));
    if (len == 0) return 0;

    if (bpf_probe_read_user(e->data, len, (void *)a->buf_ptr) != 0) return 0;

    bump(STAT_CAPTURED);

    __u64 cgid = bpf_get_current_cgroup_id();
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    __u16 dport = 0;
    __u32 daddr = 0;
    __u64 skey = (id & 0xFFFFFFFF00000000ULL) | a->fd;
    struct sock_tuple *st = bpf_map_lookup_elem(&sock_info, &skey);
    if (st) { dport = st->dport; daddr = st->daddr; }

    int req = looks_like_request(e->data, len);
    int resp = looks_like_response(e->data, len);
    __u64 conn = a->ssl_ptr;

    if (!req && !resp) {
        /* Either a body continuation of a message already reported, or genuinely
         * not HTTP. Only the former is worth anything. */
        if (conn == 0 || !bpf_map_lookup_elem(&pending_msg, &conn)) return 0;

        __u8 body_mask = classify(e->data, len);

        /* The field names come from here, not from the header write.
         *
         * This branch is the body — the header write that preceded it carries
         * the status line and headers and no JSON at all. It is also the only
         * place CVV and DOB can be recognised, so the mask is extended before
         * the emit test rather than after it: a body whose only finding is a
         * `cvv` key would otherwise have been dropped as uninteresting. */
        char fields[FIELDS_BYTES] = {};
        __u8 flen = extract_fields(e->data, len, fields, &body_mask);

        if (body_mask == 0 && flen == 0) return 0;  /* nothing found */

        struct event *cont = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
        if (!cont) return 0;
        __builtin_memset(cont, 0, sizeof(struct event));
        cont->wall_ns        = bpf_ktime_get_ns();
        cont->pid            = pid;
        cont->cgroup_id      = cgid;
        cont->conn_key       = conn;
        cont->is_continuation = 1;
        cont->data_classes   = body_mask;
        cont->data_len       = 0;   /* the body itself never leaves the kernel */
        cont->fields_len     = flen;
        __builtin_memcpy(cont->fields, fields, FIELDS_BYTES);
        bpf_ringbuf_submit(cont, 0);
        bump(STAT_CONTINUATION);
        return 0;
    }

    if (!should_emit(cgid, dport, signature(cgid, dport, e->data))) return 0;

    e->wall_ns      = bpf_ktime_get_ns();
    e->pid          = pid;
    e->cgroup_id    = cgid;
    e->data_len     = len;
    e->dport        = dport;
    e->daddr        = daddr;
    e->direction    = dir;
    e->is_request   = req ? 1 : 0;
    e->data_classes = classify(e->data, len);

    /* A small response whose body arrived in the same write as its headers never
     * produces a continuation, so extracting only there would miss exactly the
     * endpoints with the smallest responses. */
    char hdr_fields[FIELDS_BYTES] = {};
    __u8 hdr_flen = 0;
    if (resp) hdr_flen = extract_fields(e->data, len, hdr_fields, &e->data_classes);

    /* Mark the connection so the body write that follows can be joined to this
     * message rather than discarded. */
    if (conn != 0) {
        __u64 now = bpf_ktime_get_ns();
        bpf_map_update_elem(&pending_msg, &conn, &now, BPF_ANY);
    }

    /* The reservation size must be a compile-time constant: the verifier needs a
     * fixed bound on the region being written. A variable-length reserve, and
     * the variable-length __builtin_memcpy that went with it, are both rejected
     * outright — BPF has no memcpy with a runtime length. The record is
     * therefore fixed size and data_len tells userspace how much of it is real.
     */
    struct event *slot = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!slot) return 0;   /* loss is counted by the kernel and exported */

    slot->wall_ns      = e->wall_ns;
    slot->pid          = e->pid;
    slot->cgroup_id    = e->cgroup_id;
    slot->data_len     = len;
    slot->dport        = e->dport;
    slot->daddr        = e->daddr;
    slot->direction    = e->direction;
    slot->is_request   = e->is_request;
    slot->data_classes = e->data_classes;
    slot->is_continuation = 0;
    slot->fields_len   = hdr_flen;
    slot->conn_key     = conn;
    __builtin_memcpy(slot->data, e->data, SCAN_BYTES);
    __builtin_memcpy(slot->fields, hdr_fields, FIELDS_BYTES);

    bpf_ringbuf_submit(slot, 0);
    bump(STAT_EMITTED);
    return 0;
}

// ── OpenSSL ─────────────────────────────────────────────────────────────────
SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_enter, void *ssl, const void *buf, int num) {
    __u64 id = bpf_get_current_pid_tgid();
    struct ssl_args a = {};
    a.ssl_ptr = (__u64)ssl;   /* connection identity */
    a.buf_ptr = (__u64)buf;
    a.num = num;
    a.fd = 0;   // resolved by the companion kprobes; offsets vary by version
    bpf_map_update_elem(&active_ssl, &id, &a, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(ssl_write_exit, int ret) {
    if (ret <= 0) return 0;
    __u64 id = bpf_get_current_pid_tgid();
    struct ssl_args *a = bpf_map_lookup_elem(&active_ssl, &id);
    if (!a) return 0;
    handle_plaintext(a, ret, DIR_EGRESS);
    bpf_map_delete_elem(&active_ssl, &id);
    return 0;
}

SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_enter, void *ssl, void *buf, int num) {
    __u64 id = bpf_get_current_pid_tgid();
    struct ssl_args a = {};
    a.ssl_ptr = (__u64)ssl;   /* connection identity */
    a.buf_ptr = (__u64)buf;   // empty at entry; the return probe reads it
    a.num = num;
    a.fd = 0;
    bpf_map_update_elem(&active_ssl, &id, &a, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ssl_read_exit, int ret) {
    if (ret <= 0) return 0;
    __u64 id = bpf_get_current_pid_tgid();
    struct ssl_args *a = bpf_map_lookup_elem(&active_ssl, &id);
    if (!a) return 0;
    handle_plaintext(a, ret, DIR_INGRESS);
    bpf_map_delete_elem(&active_ssl, &id);
    return 0;
}

// ── OpenSSL, the _ex forms ──────────────────────────────────────────────────
//
// CPython does not call SSL_write or SSL_read. Its _ssl module is linked
// against SSL_write_ex and SSL_read_ex, and probing only the classic entry
// points made every Python service in an estate invisible — not degraded,
// absent. The estate here is Python, and the whole of it went unobserved while
// the agent reported healthy capture from the one workload that happened to be
// curl.
//
//   int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written);
//   int SSL_read_ex (SSL *s, void *buf, size_t num, size_t *readbytes);
//
// Both return 1 on success and write the byte count through the fourth
// argument, so the length has to be read back from user memory at return.
static __always_inline int ssl_ex_enter(void *ssl, void *buf, __u64 num, void *count) {
    __u64 id = bpf_get_current_pid_tgid();
    struct ssl_args a = {};
    a.ssl_ptr   = (__u64)ssl;
    a.buf_ptr   = (__u64)buf;
    a.num       = num > 0xffffffffULL ? 0xffffffffU : (__u32)num;
    a.fd        = 0;
    a.count_ptr = (__u64)count;
    bpf_map_update_elem(&active_ssl, &id, &a, BPF_ANY);
    return 0;
}

static __always_inline int ssl_ex_exit(int ret, __u8 dir) {
    __u64 id = bpf_get_current_pid_tgid();
    struct ssl_args *a = bpf_map_lookup_elem(&active_ssl, &id);
    if (!a) return 0;

    if (ret == 1 && a->count_ptr != 0) {
        __u64 n = 0;
        if (bpf_probe_read_user(&n, sizeof(n), (void *)a->count_ptr) == 0 && n > 0) {
            if (n > SCAN_BYTES) n = SCAN_BYTES;
            handle_plaintext(a, (int)n, dir);
        }
    }
    bpf_map_delete_elem(&active_ssl, &id);
    return 0;
}

SEC("uprobe/SSL_write_ex")
int BPF_UPROBE(ssl_write_ex_enter, void *ssl, void *buf, __u64 num, void *written) {
    return ssl_ex_enter(ssl, buf, num, written);
}

SEC("uretprobe/SSL_write_ex")
int BPF_URETPROBE(ssl_write_ex_exit, int ret) {
    return ssl_ex_exit(ret, DIR_EGRESS);
}

SEC("uprobe/SSL_read_ex")
int BPF_UPROBE(ssl_read_ex_enter, void *ssl, void *buf, __u64 num, void *readbytes) {
    /* The buffer is empty at entry; only the return probe sees data. */
    return ssl_ex_enter(ssl, buf, num, readbytes);
}

SEC("uretprobe/SSL_read_ex")
int BPF_URETPROBE(ssl_read_ex_exit, int ret) {
    return ssl_ex_exit(ret, DIR_INGRESS);
}

// ── Go crypto/tls ───────────────────────────────────────────────────────────
// Go statically links crypto/tls and never calls libssl. Its runtime also moves
// goroutine stacks, so a uretprobe cannot rely on the entry stack pointer —
// userspace attaches these at each RET instruction instead.
SEC("uprobe/go_tls_write")
int BPF_UPROBE(go_tls_write, void *conn, void *buf, int len) {
    struct ssl_args a = {};
    a.ssl_ptr = (__u64)conn;   /* connection identity */
    a.buf_ptr = (__u64)buf;
    a.num = len;
    a.fd = 0;
    if (len > 0) handle_plaintext(&a, len, DIR_EGRESS);
    return 0;
}

SEC("uprobe/go_tls_read_ret")
int BPF_UPROBE(go_tls_read_ret, void *conn, void *buf, int len) {
    struct ssl_args a = {};
    a.ssl_ptr = (__u64)conn;   /* connection identity */
    a.buf_ptr = (__u64)buf;
    a.num = len;
    a.fd = 0;
    if (len > 0) handle_plaintext(&a, len, DIR_INGRESS);
    return 0;
}

// ── socket tuple ────────────────────────────────────────────────────────────
// Maintains pid+fd -> 4-tuple so egress events can name their peer without a
// per-event /proc walk in userspace.
SEC("kprobe/security_socket_connect")
int BPF_KPROBE(sock_connect, struct socket *sock, struct sockaddr *addr, int addrlen) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    __u16 fam = 0;
    bpf_probe_read_kernel(&fam, sizeof(fam), &sin->sin_family);
    if (fam != 2 /* AF_INET */) return 0;

    struct sock_tuple t = {};
    __u16 be_port = 0;
    bpf_probe_read_kernel(&be_port, sizeof(be_port), &sin->sin_port);
    t.dport = bpf_ntohs(be_port);
    bpf_probe_read_kernel(&t.daddr, sizeof(t.daddr), &sin->sin_addr);

    __u64 key = id & 0xFFFFFFFF00000000ULL;
    bpf_map_update_elem(&sock_info, &key, &t, BPF_ANY);
    return 0;
}
