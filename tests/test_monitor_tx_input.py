#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile the real input guard/validator in host stubs; no RF or kernel tests."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'qcacld-3.0/core/hdd/src/wlan_hdd_tx_rx.c'


def extract(text, name, start_token):
    match = re.search(re.escape(start_token) + r'\s*' + name + r'\(', text)
    assert match, name
    pos = match.start()
    begin = text.index('{', pos)
    depth, end = 1, begin + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[pos:end]


class MonitorInput(unittest.TestCase):
    def test_compiled_guard_and_management_validator(self):
        text = SRC.read_text()
        guard = extract(text, 'hdd_monitor_tx_input_error', 'static const char *')
        validate = extract(text, 'hdd_injection_frame_is_valid', 'static bool')
        code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define ETH_P_ARP 0x0806
#define IEEE80211_FCTL_VERS 3
struct ieee80211_radiotap_header { uint8_t v, pad; uint16_t len; uint32_t present; };
struct ieee80211_hdr { uint16_t frame_control; uint8_t rest[22]; };
struct ieee80211_hdr_3addr { uint8_t header[24]; };
static uint16_t get_unaligned_le16(const void *p) {
 const uint8_t *b = p; return b[0] | ((uint16_t)b[1] << 8);
}
/* All accepted frames in these tests are ordinary 24-byte management headers. */
static unsigned ieee80211_hdrlen(uint16_t fc) { (void)fc; return 24; }
static bool ieee80211_is_mgmt(uint16_t fc) { return (fc & 0x0c) == 0; }
''' + guard + '\n' + validate + r'''
int main(void) {
 uint8_t packet[128] = {0}, original[128]; uint16_t rt;
 const char *err; unsigned i;
 const uint8_t subtypes[] = {0x40, 0x50, 0x80, 0xb0, 0xc0, 0xd0};
 /* Exact observed host-IPv6 shape cannot fall back to raw, in either netdev mode. */
 packet[0] = 0x60; packet[5] = 0x24; packet[7] = 1;
 for (i = 0; i < 2; i++) {
  err = hdd_monitor_tx_input_error(packet, 76, ETH_P_IPV6, i, &rt);
  assert(err && !strcmp(err, "host-network-protocol") && rt == 0);
 }
 /* Even a misleading AF_PACKET protocol cannot bypass mandatory radiotap. */
 assert(hdd_monitor_tx_input_error(packet, 76, 3, true, &rt));
 /* Valid radiotap-wrapped probes/auth/deauth/actions are retained byte-for-byte. */
 for (i = 0; i < sizeof(subtypes); i++) {
  memset(packet, 0, sizeof(packet)); packet[2] = 8; packet[8] = subtypes[i];
  memcpy(original, packet, sizeof(packet));
  assert(!hdd_monitor_tx_input_error(packet, 40, 3, true, &rt) && rt == 8);
  assert(hdd_injection_frame_is_valid(packet + rt, 40 - rt));
  assert(!memcmp(original, packet, sizeof(packet)));
 }
 /* Host protocols remain forbidden even when bytes resemble a valid wrapper. */
 assert(hdd_monitor_tx_input_error(packet, 40, ETH_P_IP, true, &rt));
 assert(hdd_monitor_tx_input_error(packet, 40, ETH_P_ARP, true, &rt));
 assert(hdd_monitor_tx_input_error(packet, 40, ETH_P_IPV6, true, &rt));
 /* Nonzero version, short header, short/oversized/header-only it_len. */
 packet[0] = 1; assert(hdd_monitor_tx_input_error(packet, 40, 3, true, &rt));
 packet[0] = 0; assert(hdd_monitor_tx_input_error(packet, 7, 3, true, &rt));
 packet[2] = 7; assert(hdd_monitor_tx_input_error(packet, 40, 3, true, &rt));
 packet[2] = 41; assert(hdd_monitor_tx_input_error(packet, 40, 3, true, &rt));
 packet[2] = 40; assert(hdd_monitor_tx_input_error(packet, 40, 3, true, &rt));
 assert(hdd_monitor_tx_input_error(NULL, 40, 3, true, &rt));
 /* Legacy raw remains allowed ONLY on non-radiotap devices. */
 memset(packet, 0, sizeof(packet)); packet[0] = 0x40;
 assert(!hdd_monitor_tx_input_error(packet, 28, 3, false, &rt) && rt == 0);
 assert(hdd_injection_frame_is_valid(packet, 28));
 assert(hdd_monitor_tx_input_error(packet, 28, 3, true, &rt));
 packet[0] = 0x41; assert(!hdd_injection_frame_is_valid(packet, 28));
 packet[0] = 0x08; assert(!hdd_injection_frame_is_valid(packet, 28));
 packet[0] = 0xd4; assert(!hdd_injection_frame_is_valid(packet, 28));
 assert(!hdd_injection_frame_is_valid(packet, 10));
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            c, exe = Path(tmp) / 'test.c', Path(tmp) / 'test'
            c.write_text(code)
            subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall',
                            '-Wextra', '-Werror', '-fsanitize=undefined,bounds',
                            str(c), '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True)

    def test_guard_precedes_allocation_and_submission(self):
        text = SRC.read_text()
        start = text.rindex('static void hdd_monitor_mode_tx_inject(')
        body = text[start:text.index('\n}', start)]
        self.assertLess(body.index('skb_linearize(skb)'),
                        body.index('hdd_monitor_tx_input_error('))
        self.assertLess(body.index('hdd_monitor_tx_input_error('),
                        body.index('req = qdf_mem_malloc('))
        self.assertIn('dev->type == ARPHRD_IEEE80211_RADIOTAP', body)
        self.assertLess(body.index('hdd_parse_radiotap_tx_params('),
                        body.index('req = qdf_mem_malloc('))
        self.assertNotIn('cds_get_conparam()', body)
        self.assertNotIn('QDF_GLOBAL_MONITOR_MODE', body)


if __name__ == '__main__':
    unittest.main(verbosity=2)
