/*
 * Copyright (c) 2026 Girish Kumar
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OPENVSWITCH_CT_SHM_H
#define OPENVSWITCH_CT_SHM_H 1

/*
 * Versioned ABI for userspace conntrack event logging over a file-backed
 * POSIX shared mapping whose backing file lives in OVS_RUNDIR (typically
 * /var/run/openvswitch/ovs-ct-shm).
 *
 * This header is standalone: it uses only ISO C fixed-width types and
 * does not include any OVS-internal headers.  Field names and meanings
 * match lib/ct-dpif.h (struct ct_dpif_entry / struct ct_dpif_tuple) so
 * the writer can copy dump-facing members into a record.
 *
 * Independent readers are written from the header alone.  Check magic
 * and version first, then use the size fields from the live header (the
 * constants below are defaults for writers, not values a reader may
 * hardcode).
 *
 * Layout of the shared mapping (ABI v2):
 *
 *   [ struct ovs_ct_shm_hdr ]               exactly 4096 bytes
 *   offset = hdr.rings_offset (page-aligned)
 *   for ring in 0 .. n_rings-1:             each ring_stride, page-aligned
 *       [ struct ovs_ct_shm_ring ]          cache-line padded control
 *       [ struct ovs_ct_shm_record x N ]    N = hdr.ring_capacity; 320 B
 *       [ pad to page ]
 *   total mapping size rounded up to a page
 *
 * One ring per WRITER THREAD, not per PMD only.  PMD threads emit
 * NEW/UPDATE/INVALID from the execute path.  The ct_clean thread has
 * its own ring and emits EXPIRE there.  Other non-PMD threads that
 * create CT records get ROLE_OTHER rings.  n_rings must cover all of
 * them.
 *
 * Integers other than L3 addresses and L4 ports/ICMP fields are native
 * endian of the writer (same host as the reader).  Addresses and ports
 * are stored in network byte order, matching ct_dpif_tuple.
 *
 * Write path (single writer per ring): no atomics.  At most a fence:
 *
 *   1. Fill records[write_idx & (capacity-1)] with ordinary stores.
 *   2. Memory fence so the payload is visible before the index.
 *   3. Plain store of write_idx + 1.
 *
 * The ring only publishes write_idx.  The producer always writes
 * (overwrites the oldest slot).  Each reader keeps its own cursor.
 * If write_idx - my_cursor exceeds capacity, that reader overran and
 * resyncs.  Never blocks, never allocates, never VLOGs on the write
 * path.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
#define OVS_CT_SHM_PACKED       __attribute__((packed))
#define OVS_CT_SHM_ALIGNED(n)   __attribute__((aligned(n)))
#else
#define OVS_CT_SHM_PACKED
#define OVS_CT_SHM_ALIGNED(n)
#endif

#ifdef __cplusplus
#define OVS_CT_SHM_STATIC_ASSERT static_assert
#if __cplusplus >= 201103L
#define OVS_CT_SHM_ALIGNOF alignof
#else
#define OVS_CT_SHM_ALIGNOF __alignof__
#endif
#else
#define OVS_CT_SHM_STATIC_ASSERT _Static_assert
#define OVS_CT_SHM_ALIGNOF _Alignof
#endif

/* Segment and per-record magic: ASCII "CTLG" / "CTRE". */
#define OVS_CT_SHM_MAGIC            0x43544c47u
#define OVS_CT_SHM_REC_MAGIC        0x43545245u

/* Bump on any incompatible change to header, ring, or record layout.
 * v2: 4K header, 320-byte cache-line-aligned records, page-aligned
 * rings, per-writer-thread rings, thread_id + thread_role. */
#define OVS_CT_SHM_VERSION          2u

/* Defaults for writers filling a new header.  Readers must use the
 * live header fields after checking magic + version. */
#define OVS_CT_SHM_HDR_SIZE         4096u
#define OVS_CT_SHM_PAGE_SIZE        4096u
#define OVS_CT_SHM_CACHE_LINE       64u
#define OVS_CT_SHM_RECORD_SIZE      320u
#define OVS_CT_SHM_RING_CTRL_SIZE   128u

/* Backing file: $OVS_RUNDIR/<basename>, typically
 * /var/run/openvswitch/ovs-ct-shm.  Not a nameless /dev/shm object. */
#define OVS_CT_SHM_DEFAULT_BASENAME "ovs-ct-shm"
#define OVS_CT_SHM_DEFAULT_DIR      "/var/run/openvswitch"

/* Fixed helper-name buffer, including the trailing NUL.  Never a
 * pointer. */
#define OVS_CT_SHM_HELPER_NAME_LEN  32

/* Power-of-two ring depth used unless the creator overrides it. */
#define OVS_CT_SHM_DEFAULT_CAPACITY 65536u

/* Default number of rings (one per writer thread).  Must cover PMDs,
 * ct_clean, and other non-PMD writers. */
#define OVS_CT_SHM_DEFAULT_N_RINGS  16u

/* ---------------------------------------------------------------------- */
/* Event type (not present on dpctl dump-conntrack). */
/* ---------------------------------------------------------------------- */

enum ovs_ct_shm_event {
    OVS_CT_SHM_EV_NEW     = 1,  /* Conn inserted into the CT table. */
    OVS_CT_SHM_EV_UPDATE  = 2,  /* CS_* / TCP/SCTP state changed. */
    OVS_CT_SHM_EV_EXPIRE  = 3,  /* Conn removed by timeout/sweep/flush. */
    OVS_CT_SHM_EV_INVALID = 4   /* Packet failed validation. */
};

/* Bits for hdr.event_mask (which events the writer will emit). */
#define OVS_CT_SHM_MASK_NEW         (1u << 0)
#define OVS_CT_SHM_MASK_UPDATE      (1u << 1)
#define OVS_CT_SHM_MASK_EXPIRE      (1u << 2)
#define OVS_CT_SHM_MASK_INVALID     (1u << 3)
#define OVS_CT_SHM_MASK_ALL         0xfu

/* Bits for ovs_ct_shm_record.rec_flags. */
#define OVS_CT_SHM_RF_HAVE_LABELS  (1u << 0)  /* Labels were set. */
#define OVS_CT_SHM_RF_HAVE_PARENT  (1u << 1)  /* tuple_parent populated. */
#define OVS_CT_SHM_RF_HAVE_HELPER  (1u << 2)  /* helper_name non-empty. */
#define OVS_CT_SHM_RF_TIME_MONO    (1u << 3)  /* time_ns is monotonic. */
#define OVS_CT_SHM_RF_TIME_TSC     (1u << 4)  /* time_ns actually holds TSC. */

/* Writer-thread role.  Replaces v1 core_id-only identity. */
enum ovs_ct_shm_thread_role {
    OVS_CT_SHM_ROLE_PMD      = 1,  /* PMD execute: NEW/UPDATE/INVALID. */
    OVS_CT_SHM_ROLE_CT_CLEAN = 2,  /* ct_clean thread: EXPIRE. */
    OVS_CT_SHM_ROLE_OTHER    = 3   /* Other non-PMD writer. */
};

/* ---------------------------------------------------------------------- */
/* Connection 5-tuple, matching struct ct_dpif_tuple. */
/* ---------------------------------------------------------------------- */

struct ovs_ct_shm_tuple {
    uint16_t l3_type;           /* Address family: AF_INET or AF_INET6. */
    uint8_t  ip_proto;          /* IPPROTO_TCP, UDP, SCTP, ICMP, ... */
    uint8_t  pad;               /* Align src[] to 4 bytes; must be zero. */
    uint8_t  src[16];           /* Network-order address.  IPv4 uses
                                 * [0..3] as a big-endian IPv4 address
                                 * (rest zero). */
    uint8_t  dst[16];           /* Same encoding as src. */
    union {
        uint16_t src_port;      /* L4 source port, network byte order. */
        uint16_t icmp_id;       /* ICMP/ICMPv6 identifier, network order. */
    };
    union {
        uint16_t dst_port;      /* L4 dest port, network byte order. */
        struct {
            uint8_t icmp_type;
            uint8_t icmp_code;
        };
    };
} OVS_CT_SHM_PACKED;

/* ---------------------------------------------------------------------- */
/* Counters and timestamps, matching ct_dpif_counters / ct_dpif_timestamp. */
/* ---------------------------------------------------------------------- */

struct ovs_ct_shm_counters {
    uint64_t packets;           /* Packets in this direction. */
    uint64_t bytes;             /* Bytes in this direction. */
} OVS_CT_SHM_PACKED;

struct ovs_ct_shm_timestamp {
    uint64_t start_ns;          /* Creation time, ns since Unix epoch. */
    uint64_t stop_ns;           /* Deletion time, ns since Unix epoch;
                                 * 0 while the connection is still alive. */
} OVS_CT_SHM_PACKED;

/* ---------------------------------------------------------------------- */
/* Protocol state, matching struct ct_dpif_protoinfo.
 * TCP state_* values are CT_DPIF_TCPS_* (CLOSED, LISTEN, SYN_SENT,
 * SYN_RECV, ESTABLISHED, CLOSE_WAIT, FIN_WAIT_1, CLOSING, LAST_ACK,
 * FIN_WAIT_2, TIME_WAIT).  TCP flags_* are CT_DPIF_TCPF_* bits.  SCTP
 * state is CT_DPIF_SCTP_STATE_*. */
/* ---------------------------------------------------------------------- */

struct ovs_ct_shm_protoinfo {
    uint16_t proto;             /* IPPROTO_* selecting the union arm. */
    uint8_t  pad[2];            /* Must be zero. */
    union {
        struct {
            uint8_t state_orig;
            uint8_t state_reply;
            uint8_t wscale_orig;
            uint8_t wscale_reply;
            uint8_t flags_orig;
            uint8_t flags_reply;
            uint8_t pad_tcp[2]; /* Keep the union 12 bytes. */
        } tcp;
        struct {
            uint8_t  state;
            uint8_t  pad_sctp[3];
            uint32_t vtag_orig;
            uint32_t vtag_reply;
        } sctp;
    };
} OVS_CT_SHM_PACKED;

/* ---------------------------------------------------------------------- */
/* One event record.  Packed payload padded to 320 bytes (5 cache lines)
 * and aligned to 64.  v1 was 280 packed; v2 pads 40 bytes so arrays of
 * records stay cache-line aligned. */
/* ---------------------------------------------------------------------- */

struct ovs_ct_shm_record {
    /* --- ABI / event metadata (not in dump-conntrack) --- */
    uint32_t magic;             /* OVS_CT_SHM_REC_MAGIC. */
    uint16_t abi_version;       /* OVS_CT_SHM_VERSION at write time. */
    uint16_t event;             /* enum ovs_ct_shm_event. */

    uint32_t thread_id;         /* Writer thread identity. */
    uint16_t thread_role;       /* enum ovs_ct_shm_thread_role. */
    uint16_t rec_flags;         /* OVS_CT_SHM_RF_*. */

    uint64_t time_ns;           /* CLOCK_MONOTONIC ns, or TSC if
                                 * OVS_CT_SHM_RF_TIME_TSC is set. */

    /* --- Identity (ct_dpif_entry const members) --- */
    uint32_t id;                /* Conntrack id. */
    uint16_t zone;              /* CT zone. */
    uint16_t pad1;              /* Must be zero. */
    uint32_t mark;              /* nfmark / ct_mark. */
    uint32_t status;            /* CS_* / CT_DPIF_STATUS_* dump form. */
    uint32_t timeout;           /* Remaining timeout, seconds. */
    uint32_t pad2;              /* Must be zero. */

    /* ovs_u128 labels as .u64.lo / .u64.hi.  memcpy of 16 bytes from
     * ct_dpif_entry.labels is valid on the writer host. */
    uint64_t labels_lo;
    uint64_t labels_hi;

    struct ovs_ct_shm_tuple tuple_orig;
    struct ovs_ct_shm_tuple tuple_reply;
    struct ovs_ct_shm_tuple tuple_parent;

    struct ovs_ct_shm_counters counters_orig;
    struct ovs_ct_shm_counters counters_reply;

    struct ovs_ct_shm_timestamp timestamp;

    struct ovs_ct_shm_protoinfo protoinfo;

    /* ct_dpif_helper.name is a char * and cannot be stored in SHM as a
     * pointer (it would be invalid in the reader process).  A
     * fixed-size copy is used instead; truncated names set no extra
     * flag.  All-zero means "no helper". */
    char helper_name[OVS_CT_SHM_HELPER_NAME_LEN];

    uint8_t pad_cl[40];         /* Pad 280-byte packed payload to 320. */
} OVS_CT_SHM_PACKED OVS_CT_SHM_ALIGNED(64);

/* ---------------------------------------------------------------------- */
/* Per-writer-thread ring control.  The ring only tracks write_idx.
 * Slot is (write_idx & (capacity - 1)).  Single writer: ordinary stores
 * plus one fence.  Readers keep a private cursor; they are not in SHM. */
/* ---------------------------------------------------------------------- */

struct ovs_ct_shm_ring {
    uint64_t write_idx;         /* Producer: next slot to fill.  Plain
                                 * store after ovs_ct_shm_payload_fence(). */
    uint8_t  pad_prod[56];      /* write_idx on its own cache line. */

    uint32_t thread_id;         /* Same id stamped into records. */
    uint16_t thread_role;       /* enum ovs_ct_shm_thread_role. */
    uint16_t reserved;          /* Must be zero. */
    uint8_t  pad_tail[56];      /* Second cache line. sizeof == 128. */
} OVS_CT_SHM_ALIGNED(64);

/* ---------------------------------------------------------------------- */
/* Shared-memory segment header.  Exactly one page (4096 bytes) so a
 * reader can map 4K, parse sizes, then map the rest. */
/* ---------------------------------------------------------------------- */

struct ovs_ct_shm_hdr {
    uint32_t magic;             /* OVS_CT_SHM_MAGIC. */
    uint32_t version;           /* OVS_CT_SHM_VERSION. */
    uint32_t hdr_size;          /* sizeof header; 4096 in v2. */
    uint32_t page_size;         /* Writer page size; 4096. */
    uint32_t cache_line;        /* Writer cache-line size; 64. */
    uint32_t record_size;       /* sizeof record; 320 in v2. */
    uint32_t n_rings;           /* One ring per writer thread. */
    uint32_t ring_capacity;     /* Slots per ring; power of two. */
    uint32_t ring_stride;       /* Bytes per ring, page-aligned. */
    uint32_t rings_offset;      /* Byte offset of ring 0; page-aligned. */
    uint32_t event_mask;        /* OVS_CT_SHM_MASK_* bits emitted. */
    uint32_t flags;             /* Reserved; must be zero in v2. */
    uint32_t pid;               /* Writer process id (ovs-vswitchd). */
    uint32_t ring_ctrl_size;    /* sizeof ring control; 128 in v2. */
    uint64_t created_ns;        /* CLOCK_REALTIME at segment creation. */
    uint8_t  reserved[4032];    /* Pad header to exactly 4096. */
} OVS_CT_SHM_PACKED OVS_CT_SHM_ALIGNED(4096);

/* ---------------------------------------------------------------------- */
/* Compile-time ABI checks. */
/* ---------------------------------------------------------------------- */

OVS_CT_SHM_STATIC_ASSERT(sizeof(struct ovs_ct_shm_tuple) == 40,
                         "ovs_ct_shm_tuple must be 40 bytes");
OVS_CT_SHM_STATIC_ASSERT(sizeof(struct ovs_ct_shm_counters) == 16,
                         "ovs_ct_shm_counters must be 16 bytes");
OVS_CT_SHM_STATIC_ASSERT(sizeof(struct ovs_ct_shm_timestamp) == 16,
                         "ovs_ct_shm_timestamp must be 16 bytes");
OVS_CT_SHM_STATIC_ASSERT(sizeof(struct ovs_ct_shm_protoinfo) == 16,
                         "ovs_ct_shm_protoinfo must be 16 bytes");
OVS_CT_SHM_STATIC_ASSERT(sizeof(struct ovs_ct_shm_record) == 320,
                         "ovs_ct_shm_record must be 320 bytes");
OVS_CT_SHM_STATIC_ASSERT(sizeof(struct ovs_ct_shm_record) % 64 == 0,
                         "ovs_ct_shm_record size must be a multiple of 64");
OVS_CT_SHM_STATIC_ASSERT(OVS_CT_SHM_ALIGNOF(struct ovs_ct_shm_record) >= 64,
                         "ovs_ct_shm_record must be cache-line aligned");
OVS_CT_SHM_STATIC_ASSERT(sizeof(struct ovs_ct_shm_ring) == 128,
                         "ovs_ct_shm_ring control must be 2 cache lines");
OVS_CT_SHM_STATIC_ASSERT(sizeof(struct ovs_ct_shm_ring) % 64 == 0,
                         "ovs_ct_shm_ring control size must be a multiple "
                         "of 64");
OVS_CT_SHM_STATIC_ASSERT(OVS_CT_SHM_ALIGNOF(struct ovs_ct_shm_ring) >= 64,
                         "ovs_ct_shm_ring control must be cache-line "
                         "aligned");
OVS_CT_SHM_STATIC_ASSERT(sizeof(struct ovs_ct_shm_hdr) == 4096,
                         "ovs_ct_shm_hdr must be exactly 4096 bytes");
OVS_CT_SHM_STATIC_ASSERT(sizeof(struct ovs_ct_shm_hdr) % 4096 == 0,
                         "ovs_ct_shm_hdr size must be a multiple of the "
                         "page size");

/* ---------------------------------------------------------------------- */
/* Layout helpers: page-aligned ring offsets from live header fields.
 * Readers never hardcode sizes except as defaults when filling a
 * header. */
/* ---------------------------------------------------------------------- */

static inline size_t
ovs_ct_shm_align_up(size_t x, size_t align)
{
    return (x + (align - 1u)) & ~(align - 1u);
}

/* Bytes occupied by one ring (control + records), rounded up to a
 * page. */
static inline size_t
ovs_ct_shm_compute_ring_stride(uint32_t ring_ctrl_size,
                               uint32_t ring_capacity,
                               uint32_t record_size,
                               uint32_t page_size)
{
    size_t raw = (size_t) ring_ctrl_size
               + (size_t) ring_capacity * (size_t) record_size;
    size_t pg = page_size ? (size_t) page_size
                          : (size_t) OVS_CT_SHM_PAGE_SIZE;

    return ovs_ct_shm_align_up(raw, pg);
}

/* Offset of ring 'r' control block from the start of the mapping. */
static inline size_t
ovs_ct_shm_ring_offset(const struct ovs_ct_shm_hdr *h, uint32_t r)
{
    return (size_t) h->rings_offset + (size_t) r * (size_t) h->ring_stride;
}

/* Offset of record slot 's' of ring 'r' from the start of the
 * mapping. */
static inline size_t
ovs_ct_shm_record_offset(const struct ovs_ct_shm_hdr *h, uint32_t r,
                         uint64_t s)
{
    return ovs_ct_shm_ring_offset(h, r)
         + (size_t) h->ring_ctrl_size
         + (size_t) (s & ((uint64_t) h->ring_capacity - 1u))
           * (size_t) h->record_size;
}

/* Total mapping size, rounded up to a page. */
static inline size_t
ovs_ct_shm_map_size(const struct ovs_ct_shm_hdr *h)
{
    size_t raw = (size_t) h->rings_offset
               + (size_t) h->n_rings * (size_t) h->ring_stride;
    size_t pg = h->page_size ? (size_t) h->page_size
                             : (size_t) OVS_CT_SHM_PAGE_SIZE;

    return ovs_ct_shm_align_up(raw, pg);
}

/*
 * Store-store + compiler barrier so record payload stores are visible
 * before the subsequent plain store of write_idx.  This is a fence,
 * not an atomic RMW and not a C11 atomic on write_idx.  write_idx
 * remains a single-writer uint64_t stored with an ordinary
 * assignment.
 */
static inline void
ovs_ct_shm_payload_fence(void)
{
#if defined(__x86_64__) || defined(__i386__)
    /* x86 TSO: a compiler barrier is enough for store-store. */
    __asm__ volatile ("" ::: "memory");
#elif defined(__aarch64__)
    __asm__ volatile ("dmb ishst" ::: "memory");
#elif defined(__GNUC__) || defined(__clang__)
    __atomic_thread_fence(__ATOMIC_RELEASE);
#else
    /* Compiler barrier only; weakly ordered CPUs need a real fence. */
#endif
}

#ifdef __cplusplus
}
#endif

#endif /* ct-shm.h */
