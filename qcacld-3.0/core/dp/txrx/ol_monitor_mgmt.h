/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _OL_MONITOR_MGMT_H_
#define _OL_MONITOR_MGMT_H_

#include <qdf_nbuf.h>
#include <qdf_types.h>

struct cdp_soc_t;

/* OL only: no dependency on the Wi-Fi 3.0 monitor rings or callback layout. */
#if defined(FEATURE_MONITOR_MODE_SUPPORT) && !defined(CONFIG_LITHIUM) && \
    !defined(CONFIG_BERYLLIUM)
void ol_monitor_mgmt_set_channel(struct cdp_soc_t *soc, uint8_t vdev_id,
                                uint32_t frequency);
void ol_monitor_mgmt_rx(struct cdp_soc_t *soc, qdf_nbuf_t frame,
                        uint32_t frequency, int32_t rssi, uint8_t status,
                        uint32_t event_pdev_id);
#else
static inline void
ol_monitor_mgmt_set_channel(struct cdp_soc_t *soc, uint8_t vdev_id,
                           uint32_t frequency)
{
}
static inline void
ol_monitor_mgmt_rx(struct cdp_soc_t *soc, qdf_nbuf_t frame,
                   uint32_t frequency, int32_t rssi, uint8_t status,
                        uint32_t event_pdev_id)
{
}
#endif
#endif
