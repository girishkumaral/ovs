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

#include <config.h>
#include "conntrack-shm.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dirs.h"
#include "openvswitch/thread.h"
#include "openvswitch/vlog.h"
#include "ovs-thread.h"
#include "smap.h"
#include "timeval.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(conntrack_shm);

bool ovs_ct_shm_enabled;

/* Maximums to keep a misconfiguration from exhausting address space.
 * The ABI itself does not impose these. */
#define OVS_CT_SHM_MAX_N_RINGS      1024u
#define OVS_CT_SHM_MAX_CAPACITY     (1u << 20)

struct ovs_ct_shm_state {
    struct ovs_mutex mutex;
    void *map;
    size_t map_size;
    int fd;
    char *path;
    uint32_t n_rings;
    uint32_t ring_capacity;
    uint32_t event_mask;
    uint32_t n_claimed;
};

static struct ovs_ct_shm_state shm = {
    .mutex = OVS_MUTEX_INITIALIZER,
    .fd = -1,
};

struct ovs_ct_shm_tls {
    struct ovs_ct_shm_ring *ring;
    uint32_t ring_idx;
    bool claimed;
};

DEFINE_STATIC_PER_THREAD_DATA(struct ovs_ct_shm_tls, shm_tls, {0});
DEFINE_STATIC_PER_THREAD_DATA(uint16_t, shm_role, OVS_CT_SHM_ROLE_OTHER);

static uint64_t
ovs_ct_shm_now_realtime_ns(void)
{
    struct timespec ts;

    xclock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t) ts.tv_sec * UINT64_C(1000000000)
           + (uint64_t) ts.tv_nsec;
}

static size_t
ovs_ct_shm_sys_page_size(void)
{
    long pg = sysconf(_SC_PAGESIZE);

    if (pg <= 0) {
        pg = OVS_CT_SHM_PAGE_SIZE;
    }
    return (size_t) pg;
}

static char *
ovs_ct_shm_make_path(void)
{
    return abs_file_name(ovs_rundir(), OVS_CT_SHM_DEFAULT_BASENAME);
}

static struct ovs_ct_shm_hdr *
ovs_ct_shm_hdr_ptr(void)
{
    return shm.map;
}

static struct ovs_ct_shm_ring *
ovs_ct_shm_ring_ptr(uint32_t r)
{
    const struct ovs_ct_shm_hdr *h = ovs_ct_shm_hdr_ptr();
    uint8_t *base;

    if (!h || r >= h->n_rings) {
        return NULL;
    }
    base = shm.map;
    return ALIGNED_CAST(struct ovs_ct_shm_ring *,
                        base + ovs_ct_shm_ring_offset(h, r));
}

static struct ovs_ct_shm_record *
ovs_ct_shm_record_ptr(const struct ovs_ct_shm_hdr *h, uint32_t r,
                      uint64_t s)
{
    uint8_t *base = shm.map;

    return ALIGNED_CAST(struct ovs_ct_shm_record *,
                        base + ovs_ct_shm_record_offset(h, r, s));
}

static int
ovs_ct_shm_map__(size_t map_size)
    OVS_REQUIRES(shm.mutex)
{
    int fd;
    void *map;

    if (!shm.path) {
        shm.path = ovs_ct_shm_make_path();
    }

    fd = open(shm.path, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        VLOG_ERR("%s: open failed (%s)", shm.path, ovs_strerror(errno));
        return errno;
    }

    if (ftruncate(fd, map_size) < 0) {
        int error = errno;

        VLOG_ERR("%s: ftruncate to %zu failed (%s)",
                 shm.path, map_size, ovs_strerror(error));
        close(fd);
        return error;
    }

    map = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        int error = errno;

        VLOG_ERR("%s: mmap of %zu bytes failed (%s)",
                 shm.path, map_size, ovs_strerror(error));
        close(fd);
        return error;
    }

    shm.fd = fd;
    shm.map = map;
    shm.map_size = map_size;
    return 0;
}

static void
ovs_ct_shm_init_header__(uint32_t n_rings, uint32_t ring_capacity,
                         uint32_t event_mask)
    OVS_REQUIRES(shm.mutex)
{
    struct ovs_ct_shm_hdr *h = shm.map;
    uint32_t stride;
    uint32_t r;

    memset(h, 0, OVS_CT_SHM_HDR_SIZE);

    stride = ovs_ct_shm_compute_ring_stride(OVS_CT_SHM_RING_CTRL_SIZE,
                                            ring_capacity,
                                            OVS_CT_SHM_RECORD_SIZE,
                                            OVS_CT_SHM_PAGE_SIZE);

    h->version = OVS_CT_SHM_VERSION;
    h->hdr_size = OVS_CT_SHM_HDR_SIZE;
    h->page_size = OVS_CT_SHM_PAGE_SIZE;
    h->cache_line = OVS_CT_SHM_CACHE_LINE;
    h->record_size = OVS_CT_SHM_RECORD_SIZE;
    h->n_rings = n_rings;
    h->ring_capacity = ring_capacity;
    h->ring_stride = stride;
    h->rings_offset = OVS_CT_SHM_HDR_SIZE;
    h->event_mask = event_mask;
    h->flags = 0;
    h->pid = (uint32_t) getpid();
    h->ring_ctrl_size = OVS_CT_SHM_RING_CTRL_SIZE;
    h->created_ns = ovs_ct_shm_now_realtime_ns();

    for (r = 0; r < n_rings; r++) {
        struct ovs_ct_shm_ring *ring = ovs_ct_shm_ring_ptr(r);

        memset(ring, 0, sizeof *ring);
    }

    shm.n_rings = n_rings;
    shm.ring_capacity = ring_capacity;
    shm.event_mask = event_mask;
    shm.n_claimed = 0;

    /* Publish magic last so a reader mapping 4K first never sees a
     * half-initialized header. */
    ovs_ct_shm_payload_fence();
    h->magic = OVS_CT_SHM_MAGIC;
}

static int
ovs_ct_shm_enable__(uint32_t n_rings, uint32_t ring_capacity,
                    uint32_t event_mask)
    OVS_REQUIRES(shm.mutex)
{
    struct ovs_ct_shm_hdr probe;
    size_t map_size;
    size_t sys_pg;
    int error;

    if (!n_rings) {
        n_rings = OVS_CT_SHM_DEFAULT_N_RINGS;
    }
    if (n_rings > OVS_CT_SHM_MAX_N_RINGS) {
        VLOG_WARN("ct-shm-n-rings %u exceeds %u; clamping",
                  n_rings, OVS_CT_SHM_MAX_N_RINGS);
        n_rings = OVS_CT_SHM_MAX_N_RINGS;
    }
    if (!ring_capacity) {
        ring_capacity = OVS_CT_SHM_DEFAULT_CAPACITY;
    }
    if (!is_pow2(ring_capacity)) {
        VLOG_ERR("ct-shm-ring-capacity %u is not a power of two",
                 ring_capacity);
        return EINVAL;
    }
    if (ring_capacity > OVS_CT_SHM_MAX_CAPACITY) {
        VLOG_WARN("ct-shm-ring-capacity %u exceeds %u; clamping",
                  ring_capacity, OVS_CT_SHM_MAX_CAPACITY);
        ring_capacity = OVS_CT_SHM_MAX_CAPACITY;
    }
    if (!event_mask) {
        event_mask = OVS_CT_SHM_MASK_ALL;
    }

    if (ovs_ct_shm_enabled
        && shm.n_rings == n_rings
        && shm.ring_capacity == ring_capacity
        && shm.event_mask == event_mask) {
        return 0;
    }

    memset(&probe, 0, sizeof probe);
    probe.hdr_size = OVS_CT_SHM_HDR_SIZE;
    probe.page_size = OVS_CT_SHM_PAGE_SIZE;
    probe.record_size = OVS_CT_SHM_RECORD_SIZE;
    probe.n_rings = n_rings;
    probe.ring_capacity = ring_capacity;
    probe.ring_stride = ovs_ct_shm_compute_ring_stride(
        OVS_CT_SHM_RING_CTRL_SIZE, ring_capacity, OVS_CT_SHM_RECORD_SIZE,
        OVS_CT_SHM_PAGE_SIZE);
    probe.rings_offset = OVS_CT_SHM_HDR_SIZE;
    probe.ring_ctrl_size = OVS_CT_SHM_RING_CTRL_SIZE;

    map_size = ovs_ct_shm_map_size(&probe);
    sys_pg = ovs_ct_shm_sys_page_size();
    map_size = ovs_ct_shm_align_up(map_size, sys_pg);

    if (shm.map) {
        if (shm.n_rings != n_rings
            || shm.ring_capacity != ring_capacity) {
            VLOG_WARN("conntrack SHM log already mapped (%u rings, "
                      "%u slots); size changes require a restart",
                      shm.n_rings, shm.ring_capacity);
        } else {
            shm.event_mask = event_mask;
            ovs_ct_shm_hdr_ptr()->event_mask = event_mask;
        }
        ovs_ct_shm_enabled = true;
        return 0;
    }

    error = ovs_ct_shm_map__(map_size);
    if (error) {
        return error;
    }

    ovs_ct_shm_init_header__(n_rings, ring_capacity, event_mask);
    ovs_ct_shm_payload_fence();
    ovs_ct_shm_enabled = true;
    VLOG_INFO("conntrack SHM log enabled at %s (%u rings, %u slots, "
              "mask 0x%x)", shm.path, n_rings, ring_capacity, event_mask);
    return 0;
}

static void
ovs_ct_shm_disable__(void)
    OVS_REQUIRES(shm.mutex)
{
    if (!ovs_ct_shm_enabled && !shm.map) {
        return;
    }

    /* Leave the mapping in place so in-flight writers cannot fault,
     * and never unlink the file. */
    ovs_ct_shm_enabled = false;
    VLOG_INFO("conntrack SHM log disabled (file %s left in place)",
              shm.path ? shm.path : OVS_CT_SHM_DEFAULT_BASENAME);
}

int
ovs_ct_shm_set_config(bool enable, uint32_t n_rings,
                      uint32_t ring_capacity, uint32_t event_mask)
{
    int error = 0;

    ovs_mutex_lock(&shm.mutex);
    if (enable) {
        error = ovs_ct_shm_enable__(n_rings, ring_capacity, event_mask);
    } else {
        ovs_ct_shm_disable__();
    }
    ovs_mutex_unlock(&shm.mutex);
    return error;
}

void
ovs_ct_shm_apply_other_config(const struct smap *cfg)
{
    bool enable;
    uint32_t n_rings;
    uint32_t cap;
    uint32_t mask;

    if (!cfg) {
        ovs_ct_shm_set_config(false, 0, 0, 0);
        return;
    }

    enable = smap_get_bool(cfg, "ct-shm-enable", false);
    n_rings = smap_get_uint(cfg, "ct-shm-n-rings",
                            OVS_CT_SHM_DEFAULT_N_RINGS);
    cap = smap_get_uint(cfg, "ct-shm-ring-capacity",
                        OVS_CT_SHM_DEFAULT_CAPACITY);
    mask = smap_get_uint(cfg, "ct-shm-event-mask", OVS_CT_SHM_MASK_ALL);
    ovs_ct_shm_set_config(enable, n_rings, cap, mask);
}

void
ovs_ct_shm_thread_role_set(enum ovs_ct_shm_thread_role role)
{
    *shm_role_get() = (uint16_t) role;
}

const char *
ovs_ct_shm_path(void)
{
    const char *path;

    ovs_mutex_lock(&shm.mutex);
    if (!shm.path) {
        shm.path = ovs_ct_shm_make_path();
    }
    path = shm.path;
    ovs_mutex_unlock(&shm.mutex);
    return path;
}

static bool
ovs_ct_shm_claim_ring(struct ovs_ct_shm_tls *tls)
{
    uint32_t idx;
    struct ovs_ct_shm_ring *ring;
    uint16_t role = *shm_role_get();
    uint32_t thread_id = ovsthread_id_self();

    ovs_mutex_lock(&shm.mutex);
    if (!ovs_ct_shm_enabled || !shm.map) {
        ovs_mutex_unlock(&shm.mutex);
        tls->claimed = true;
        tls->ring = NULL;
        return false;
    }
    if (shm.n_claimed >= shm.n_rings) {
        ovs_mutex_unlock(&shm.mutex);
        tls->claimed = true;
        tls->ring = NULL;
        return false;
    }
    idx = shm.n_claimed++;
    ring = ovs_ct_shm_ring_ptr(idx);
    ring->thread_id = thread_id;
    ring->thread_role = role;
    ring->reserved = 0;
    ovs_mutex_unlock(&shm.mutex);

    tls->ring = ring;
    tls->ring_idx = idx;
    tls->claimed = true;
    return true;
}

void
ovs_ct_shm_emit(const struct ovs_ct_shm_record *src)
{
    struct ovs_ct_shm_tls *tls;
    struct ovs_ct_shm_hdr *h;
    struct ovs_ct_shm_ring *ring;
    struct ovs_ct_shm_record *dst;
    uint32_t mask_bit;
    uint32_t r;
    uint64_t idx;

    if (OVS_LIKELY(!ovs_ct_shm_enabled) || !src) {
        return;
    }

    if (src->event < OVS_CT_SHM_EV_NEW
        || src->event > OVS_CT_SHM_EV_INVALID) {
        return;
    }
    mask_bit = 1u << (src->event - 1);

    h = ovs_ct_shm_hdr_ptr();
    if (OVS_UNLIKELY(!h)) {
        return;
    }
    if (!(h->event_mask & mask_bit)) {
        return;
    }

    tls = shm_tls_get();
    if (OVS_UNLIKELY(!tls->claimed)) {
        if (!ovs_ct_shm_claim_ring(tls)) {
            return;
        }
    }
    ring = tls->ring;
    if (OVS_UNLIKELY(!ring)) {
        return;
    }

    r = tls->ring_idx;
    idx = ring->write_idx;
    dst = ovs_ct_shm_record_ptr(h, r, idx);
    memcpy(dst, src, sizeof *dst);
    dst->thread_id = ovsthread_id_self();
    dst->thread_role = *shm_role_get();

    ovs_ct_shm_payload_fence();
    ring->write_idx = idx + 1;
}
