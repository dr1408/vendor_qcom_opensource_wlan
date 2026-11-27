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
#include "wma_frame_inject.h"
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

/*
 * Mode 0 is not global monitor mode: firmware keeps its normal STA MLME
 * personality while a separate monitor vdev exists.  Isolate foreign data
 * indications from normal/helper STA vdevs before monitor activation.  The
 * monitor vdev itself is deliberately excluded so raw monitor and packet
 * capture delivery remain unchanged.
 */
static int hdd_mode0_rx_isolation(struct hdd_adapter *mon_adapter, bool enable)
{
	struct hdd_adapter *sta_adapter;
	tp_wma_handle wma;
	QDF_STATUS status;

	if (cds_get_conparam() != QDF_GLOBAL_MISSION_MODE)
		return 0;
	if (!mon_adapter || !mon_adapter->hdd_ctx)
		return -EINVAL;

	sta_adapter = hdd_get_adapter(mon_adapter->hdd_ctx, QDF_STA_MODE);
	if (!sta_adapter) {
		hdd_err("MONRXISO no normal STA adapter for monitor vdev=%u",
			mon_adapter->vdev_id);
		return -EINVAL;
	}
	if (enable && hdd_cm_is_vdev_associated(sta_adapter)) {
		hdd_err("MONRXISO refusing mode0 activation: STA vdev=%u remains associated",
			sta_adapter->vdev_id);
		return -EBUSY;
	}

	wma = cds_get_context(QDF_MODULE_ID_WMA);
	if (!wma) {
		hdd_err("MONRXISO no WMA context sta=%u mon=%u enable=%u",
			sta_adapter->vdev_id, mon_adapter->vdev_id, enable);
		return -EINVAL;
	}

	status = wma_injection_set_mode0_rx_isolation(wma,
						       sta_adapter->vdev_id,
						       mon_adapter->vdev_id, enable);
	hdd_info("MONRXISO %s con=0 sta_vdev=%u mon_vdev=%u sta_assoc=%u status=%d",
		 enable ? "apply" : "restore", sta_adapter->vdev_id,
		 mon_adapter->vdev_id, hdd_cm_is_vdev_associated(sta_adapter), status);
	return QDF_IS_STATUS_ERROR(status) ? -EIO : 0;
}

int hdd_enable_monitor_mode(struct net_device *dev)
{
	void *soc = cds_get_context(QDF_MODULE_ID_SOC);
	uint8_t vdev_id;
	int ret;
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);

	hdd_enter_dev(dev);

	vdev_id = cdp_get_mon_vdev_from_pdev(soc, OL_TXRX_PDEV_ID);
	if (vdev_id < 0)
		return -EINVAL;

	pr_info("MONDIAG enable con=%u dev=%s mon_vdev=%u adapter_vdev=%u mode=%u mac=%pM dp_pdev=%u\n",
		cds_get_conparam(), dev->name, vdev_id, adapter ? adapter->vdev_id : 0xff,
		adapter ? adapter->device_mode : 0xff,
		adapter ? adapter->mac_addr.bytes : NULL, OL_TXRX_PDEV_ID);
	ret = hdd_mode0_rx_isolation(adapter, true);
	if (ret) {
		hdd_err("MONRXISO activation blocked: mon_vdev=%u status=%d", vdev_id,
			ret);
		return ret;
	}
	ret = cdp_set_monitor_mode(soc, vdev_id, false);
	if (ret) {
		/* cdp activation did not take ownership: immediately undo the
		 * normal-STA filter so a failed monitor open cannot alter STA RX. */
		hdd_mode0_rx_isolation(adapter, false);
	}
	pr_info("MONDIAG enable-result con=%u mon_vdev=%u status=%d\n",
		cds_get_conparam(), vdev_id, ret);

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
	int vdev_id;
	int ret;
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);

	hdd_enter_dev(dev);

	vdev_id = cdp_get_mon_vdev_from_pdev(soc, OL_TXRX_PDEV_ID);
	if (vdev_id < 0)
		return -EINVAL;

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

	/* Restore while WMI is still alive. hdd_frame_inject_disable() has
	 * already destroyed the helper, and cdp_reset_monitor_mode() can begin
	 * monitor-vdev teardown immediately afterwards. */
	if (adapter) {
		int iso_ret = hdd_mode0_rx_isolation(adapter, false);

		if (iso_ret)
			hdd_warn("MONRXISO restore failed before monitor reset: %d",
				 iso_ret);
	}
	ret = cdp_reset_monitor_mode(soc, OL_TXRX_PDEV_ID, false);

	return ret;
}
