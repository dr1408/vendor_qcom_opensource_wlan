/*
 * Copyright (c) 2017-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include "wlan_hdd_includes.h"
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <cds_sched.h>
#include <cds_utils.h>
#include "wlan_hdd_rx_monitor.h"
#include "ol_txrx.h"
#include "ol_monitor_mgmt.h"
#include "cdp_txrx_mon.h"
#ifdef FEATURE_FRAME_INJECTION_SUPPORT
#include "wlan_hdd_frame_inject.h"
#endif

void hdd_rx_monitor_callback(ol_osif_vdev_handle context,
				qdf_nbuf_t rxbuf,
				void *rx_status)
{
	struct hdd_adapter *adapter;
	int rxstat;
	struct sk_buff *skb;
	struct sk_buff *skb_next;
	unsigned int cpu_index;
	struct hdd_tx_rx_stats *stats;

	qdf_assert(context);
	qdf_assert(rxbuf);

	adapter = (struct hdd_adapter *)context;
	if (WLAN_HDD_ADAPTER_MAGIC != adapter->magic) {
		QDF_TRACE(QDF_MODULE_ID_HDD_DATA, QDF_TRACE_LEVEL_ERROR,
			"invalid adapter %pK", adapter);
		return;
	}

	cpu_index = wlan_hdd_get_cpu();
	stats = &adapter->hdd_stats.tx_rx_stats;

	/* walk the chain until all are processed */
	skb = (struct sk_buff *)rxbuf;
	while (skb) {
		skb_next = skb->next;
		skb->dev = adapter->dev;
		skb->pkt_type = PACKET_OTHERHOST;
		skb->protocol = htons(ETH_P_802_2);
		skb_reset_mac_header(skb);

		++stats->per_cpu[cpu_index].rx_packets;
		++adapter->stats.rx_packets;
		adapter->stats.rx_bytes += skb->len;

		/* Remove SKB from internal tracking table before submitting
		 * it to stack
		 */
		qdf_net_buf_debug_release_skb(skb);

		/*
		 * If this is not a last packet on the chain
		 * Just put packet into backlog queue, not scheduling RX sirq
		 */
		if (skb->next) {
			rxstat = netif_rx(skb);
		} else {
			/*
			 * This is the last packet on the chain
			 * Scheduling rx sirq
			 */
			rxstat = netif_rx_ni(skb);
		}

		if (NET_RX_SUCCESS == rxstat)
			++stats->per_cpu[cpu_index].rx_delivered;
		else
			++stats->per_cpu[cpu_index].rx_refused;

		skb = skb_next;
	}
}

void hdd_monitor_set_rx_monitor_cb(struct ol_txrx_ops *txrx,
				ol_txrx_rx_mon_fp rx_monitor_cb)
{
	txrx->rx.mon = rx_monitor_cb;
}

int hdd_enable_monitor_mode(struct net_device *dev)
{
	void *soc = cds_get_context(QDF_MODULE_ID_SOC);
	uint8_t vdev_id;
	int ret;
	bool backend_present;
	ol_txrx_soc_handle dp_soc = soc;
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);

	hdd_enter_dev(dev);

	if (!soc || !adapter)
		return -EINVAL;
	hdd_warn("VIFDIAG monitor lookup if=%s adapter_vdev=%u",
		 dev->name, adapter->vdev_id);
	vdev_id = cdp_get_mon_vdev_from_pdev(soc, OL_TXRX_PDEV_ID);
	/* The CDP error sentinel is carried through an unsigned u8 API. */
	if (vdev_id == (uint8_t)-EINVAL)
		return -EINVAL;

	/* Do not configure another adapter during monitor teardown/recreation. */
	if (vdev_id != adapter->vdev_id) {
		hdd_warn("VIFDIAG monitor ownership mismatch if=%s adapter_vdev=%u monitor_vdev=%u",
			 dev->name, adapter->vdev_id, vdev_id);
		return -EINVAL;
	}

	/* The CDP wrapper may return success without invoking any backend. */
	backend_present = dp_soc->ops && dp_soc->ops->cmn_drv_ops &&
		dp_soc->ops->cmn_drv_ops->txrx_set_monitor_mode;
	pr_info("VIFACT cdp-monitor-request if=%s mode=%u vdev=%u backend_present=%u special=0\n",
		dev->name, cds_get_conparam(), vdev_id, backend_present);
	ret = cdp_set_monitor_mode(soc, vdev_id, false);
	pr_info("VIFACT cdp-monitor-return if=%s mode=%u vdev=%u status=%d backend_invoked=%u default_success=%u firmware_acceptance=unconfirmed\n",
		dev->name, cds_get_conparam(), vdev_id, ret,
		backend_present, !backend_present && !ret);
	hdd_warn("VIFDIAG monitor CDP request vdev=%u status=%d (not RX validation)",
		 vdev_id, ret);

#ifdef FEATURE_FRAME_INJECTION_SUPPORT
	/* Enable frame injection when monitor mode is enabled */
	if (ret == 0 && adapter) {
		if (QDF_IS_STATUS_ERROR(hdd_frame_inject_enable(adapter))) {
			hdd_warn("Failed to enable frame injection");
			/* Continue without frame injection */
		}
	}
#endif

	return ret;
}

/**
 * hdd_disable_monitor_mode() - Disable monitor mode
 * @dev: Pointer to the net_device structure
 *
 * This function disables monitor mode configuration on the hardware
 * and also disables frame injection if it was enabled.
 *
 * Return: 0 for success; non-zero for failure
 */
int hdd_disable_monitor_mode(struct net_device *dev)
{
	void *soc = cds_get_context(QDF_MODULE_ID_SOC);
	uint8_t vdev_id;
	int ret;
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);

	hdd_enter_dev(dev);

	/* Serialize capture shutdown with callback delivery before freeing adapter. */
	if (adapter)
		ol_monitor_mgmt_set_channel(soc, adapter->vdev_id, 0);
#ifdef FEATURE_FRAME_INJECTION_SUPPORT
	/* Disable frame injection when monitor mode is disabled */
	if (adapter) {
		if (QDF_IS_STATUS_ERROR(hdd_frame_inject_disable(adapter))) {
			hdd_warn("Failed to disable frame injection");
			/* Continue with monitor mode disable */
		}
	}
#endif

	if (!soc)
		return -EINVAL;
	vdev_id = cdp_get_mon_vdev_from_pdev(soc, OL_TXRX_PDEV_ID);
	if (vdev_id == (uint8_t)-EINVAL)
		return -EINVAL;
	ret = cdp_reset_monitor_mode(soc, OL_TXRX_PDEV_ID, false);
	hdd_warn("VIFDIAG monitor reset vdev=%u status=%d", vdev_id, ret);

	return ret;
}
