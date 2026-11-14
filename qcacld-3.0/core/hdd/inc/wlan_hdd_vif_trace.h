/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _WLAN_HDD_VIF_TRACE_H_
#define _WLAN_HDD_VIF_TRACE_H_

#include <linux/printk.h>
#include <linux/string.h>
#include <asm/unaligned.h>

/* Header-only diagnostics: no payload, no additional over-the-air traffic.
 * Independent ratelimiting means absence of a line is not proof of no TX.
 * Addresses are IEEE 802.11 address slots, not assumed Ethernet SA/DA.
 */
static inline void
wlan_vif_trace_frame(const char *stage, unsigned int id, unsigned int vdev,
		     unsigned int freq, const unsigned char *data,
		     unsigned int len)
{
	unsigned char a1[6] = {0}, a2[6] = {0}, a3[6] = {0}, a4[6] = {0};
	unsigned int fc, type, subtype, seq = 0, reason = 0;
	bool has_seq = false, has_reason = false, has_a4 = false;

	if (!data || len < 2) {
		pr_info_ratelimited("VIFTRACE stage=%s id=%u vdev=%u len=%u short=1\n",
			    stage, id, vdev, len);
		return;
	}
	fc = get_unaligned_le16(data);
	type = (fc >> 2) & 3;
	subtype = (fc >> 4) & 15;
	if (len >= 10)
		memcpy(a1, data + 4, 6);
	/* ACK/CTS have no Address 2. */
	if (len >= 16 && !(type == 1 && (subtype == 12 || subtype == 13)))
		memcpy(a2, data + 10, 6);
	if ((type == 0 || type == 2) && len >= 24) {
		memcpy(a3, data + 16, 6);
		seq = get_unaligned_le16(data + 22);
		has_seq = true;
	}
	if (type == 2 && (fc & 0x0300) == 0x0300 && len >= 30) {
		memcpy(a4, data + 24, 6);
		has_a4 = true;
	}
	/* Protected bodies are not interpreted as plaintext reason codes. */
	if (type == 0 && (subtype == 10 || subtype == 12) &&
	    !(fc & 0x4000) && len >= 26) {
		reason = get_unaligned_le16(data + 24);
		has_reason = true;
	}
	pr_info_ratelimited("VIFTRACE stage=%s id=%u vdev=%u freq=%u len=%u fc=%04x type=%u subtype=%u a1=%pM a2=%pM a3=%pM a4=%pM has_a4=%u seqctl=%u has_seq=%u reason=%u has_reason=%u\n",
		stage, id, vdev, freq, len, fc, type, subtype, a1, a2, a3, a4,
		has_a4, seq, has_seq, reason, has_reason);
}
#endif
