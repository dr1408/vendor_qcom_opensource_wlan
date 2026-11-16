/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _OL_MONITOR_EAPOL_VALIDATE_H_
#define _OL_MONITOR_EAPOL_VALIDATE_H_

/* Pure, bounded validators; caller supplies a DMA-unmapped linear buffer.
 * RAW and descriptor decap=3 (ETH2) have DIFFERENT header locations.
 */
struct ol_eapol_span {
	uint32_t header_len; /* 802.11 + LLC */
	uint32_t body_len;   /* EAPOL header + body */
	uint32_t mpdu_len;   /* without FCS */
	uint8_t direction;
	bool fcs;
};

enum ol_eapol_result {
	OL_EAPOL_OK,
	OL_EAPOL_NOT_KEY,
	OL_EAPOL_HEADER,
	OL_EAPOL_LENGTH,
	OL_EAPOL_FCS,
	OL_EAPOL_MISMATCH,
};

static uint32_t ol_eapol_be16(const uint8_t *p)
{
	return ((uint32_t)p[0] << 8) | p[1];
}

static enum ol_eapol_result
ol_eapol_header(const uint8_t *p, uint32_t n, uint32_t *hlen)
{
	static const uint8_t llc[] = {0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e};
	uint32_t h = 24;

	if (n < h)
		return OL_EAPOL_LENGTH;
	if ((p[0] != 0x08 && p[0] != 0x88) ||
	    ((p[1] & 3) != 1 && (p[1] & 3) != 2) ||
	    (p[1] & (0x40 | 0x04)) || (p[22] & 0x0f) || (p[10] & 1))
		return OL_EAPOL_HEADER; /* no encrypted, fragmented or four-address MPDU */
	if (p[0] == 0x88) {
		if (n < h + 2)
			return OL_EAPOL_LENGTH;
		if (p[h] & 0x80)
			return OL_EAPOL_HEADER; /* A-MSDU needs separate subframe validation */
		h += 2;
		if (p[1] & 0x80)
			h += 4;
	} else if (p[1] & 0x80) {
		return OL_EAPOL_HEADER;
	}
	if (n < h + sizeof(llc))
		return OL_EAPOL_LENGTH;
	if (qdf_mem_cmp(p + h, llc, sizeof(llc)))
		return OL_EAPOL_NOT_KEY;
	*hlen = h + sizeof(llc);
	return OL_EAPOL_OK;
}

static enum ol_eapol_result
ol_eapol_key(const uint8_t *p, uint32_t n, uint32_t *body_len)
{
	uint32_t body;

	if (n < 4)
		return OL_EAPOL_LENGTH;
	if (p[0] < 1 || p[0] > 3 || p[1] != 3)
		return OL_EAPOL_NOT_KEY;
	body = ol_eapol_be16(p + 2);
	if (body < 95 || body > n - 4)
		return OL_EAPOL_LENGTH;
	/* RSN/WPA Key descriptor, with its complete fixed prefix and key data.
	 * Do not label an arbitrary EAPOL type-3 prefix a validated Key frame.
	 */
	if (p[4] != 2 && p[4] != 254)
		return OL_EAPOL_NOT_KEY;
	if (ol_eapol_be16(p + 97) != body - 95)
		return OL_EAPOL_LENGTH;
	*body_len = body + 4;
	return OL_EAPOL_OK;
}

static enum ol_eapol_result
ol_eapol_raw(const uint8_t *p, uint32_t n, struct ol_eapol_span *span)
{
	enum ol_eapol_result result;
	uint32_t h, body, total, fcs;

	result = ol_eapol_header(p, n, &h);
	if (result != OL_EAPOL_OK)
		return result;
	result = ol_eapol_key(p + h, n - h, &body);
	if (result != OL_EAPOL_OK)
		return result;
	total = h + body;
	if (n != total && n != total + 4)
		return OL_EAPOL_LENGTH;
	span->fcs = n == total + 4;
	if (span->fcs) {
		fcs = (uint32_t)p[total] | ((uint32_t)p[total + 1] << 8) |
		      ((uint32_t)p[total + 2] << 16) |
		      ((uint32_t)p[total + 3] << 24);
		if ((crc32_le(~0U, p, total) ^ ~0U) != fcs)
			return OL_EAPOL_FCS;
	}
	span->header_len = h;
	span->body_len = body;
	span->mpdu_len = total;
	span->direction = p[1] & 3;
	return OL_EAPOL_OK;
}

static enum ol_eapol_result
ol_eapol_eth2(const uint8_t *hdr, uint32_t captured,
	      const uint8_t *eth, uint32_t n, struct ol_eapol_span *span)
{
	enum ol_eapol_result result;
	uint32_t h, body, prefix;
	uint8_t ds;

	if (n < 18)
		return OL_EAPOL_LENGTH;
	if (eth[12] != 0x88 || eth[13] != 0x8e)
		return OL_EAPOL_NOT_KEY;
	result = ol_eapol_header(hdr, captured, &h);
	if (result != OL_EAPOL_OK)
		return result;
	result = ol_eapol_key(eth + 14, n - 14, &body);
	if (result != OL_EAPOL_OK)
		return result;
	ds = hdr[1] & 3;
	/* DA/SA depend on direction; never substitute the monitor's MAC. */
	if (qdf_mem_cmp(eth, hdr + (ds == 2 ? 4 : 16), 6) ||
	    qdf_mem_cmp(eth + 6, hdr + (ds == 2 ? 16 : 10), 6))
		return OL_EAPOL_MISMATCH;
	prefix = captured - h;
	if (prefix > body)
		prefix = body;
	if (prefix < 4 || qdf_mem_cmp(hdr + h, eth + 14, prefix))
		return OL_EAPOL_MISMATCH;
	span->header_len = h;
	span->body_len = body;
	span->mpdu_len = h + body;
	span->direction = ds;
	span->fcs = false;
	return OL_EAPOL_OK;
}
#endif
