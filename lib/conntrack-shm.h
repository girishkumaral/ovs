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

#ifndef CONNTRACK_SHM_H
#define CONNTRACK_SHM_H 1

#include <stdbool.h>
#include <stdint.h>

#include "openvswitch/ct-shm.h"
#include "openvswitch/compiler.h"

struct smap;

/* Written at reconfigure; read lock-free on the hot path.  Off by
 * default: the execute / ct_clean path is one predictable false
 * branch. */
extern bool ovs_ct_shm_enabled;

static inline bool
ovs_ct_shm_is_enabled(void)
{
    return OVS_UNLIKELY(ovs_ct_shm_enabled);
}

/* Apply Open_vSwitch other_config knobs.  Missing keys keep the
 * documented defaults (disabled). */
void ovs_ct_shm_apply_other_config(const struct smap *);

/* Create or leave the mapping.  'ring_capacity' must be a power of
 * two.  Returns 0 if successful, otherwise a positive errno.  The
 * backing file is never unlinked. */
int ovs_ct_shm_set_config(bool enable, uint32_t n_rings,
                          uint32_t ring_capacity, uint32_t event_mask);

/* Stamp the calling thread's writer role.  Default is ROLE_OTHER.
 * PMD threads set ROLE_PMD; the ct_clean thread sets ROLE_CT_CLEAN. */
void ovs_ct_shm_thread_role_set(enum ovs_ct_shm_thread_role);

/* Wait-free producer.  Never blocks, never allocates, never VLOGs.
 * Overwrites the oldest slot.  No-op if disabled or if this thread
 * could not claim a ring. */
void ovs_ct_shm_emit(const struct ovs_ct_shm_record *);

/* Path of the backing file, or NULL if never configured. */
const char *ovs_ct_shm_path(void);

#endif /* conntrack-shm.h */
