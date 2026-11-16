#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Source/harness checks only; not a substitute for a kernel build or device test."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def source(path):
    return (ROOT / path).read_text()


def function(text, name):
    start = text.index(name + '(')
    start = text.rfind('QDF_STATUS', 0, start)
    begin = text.index('{', start)
    depth = 1
    end = begin + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


PRELUDE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stddef.h>
#define READ_ONCE(x) (x)
#define module_param(...)
#define MODULE_PARM_DESC(...)
#define module_param_cb(name, ops, arg, perm) \
 static const void *use_##name __attribute__((unused)) = (ops)
static void diag_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void diag_log(const char *fmt, ...) { (void)fmt; }
#define pr_info(...) diag_log(__VA_ARGS__)
#define pr_info_ratelimited(...) diag_log(__VA_ARGS__)
'''


class Diagnostics(unittest.TestCase):
    def compile_run(self, code):
        with tempfile.TemporaryDirectory() as tmp:
            c = Path(tmp) / 'test.c'
            exe = Path(tmp) / 'test'
            c.write_text(PRELUDE + code)
            subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall',
                            '-Wextra', '-Werror', '-fsanitize=undefined,bounds',
                            str(c), '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True)

    def test_wmi_submission_results_preserved(self):
        text = source('qca-wifi-host-cmn/wmi/src/wmi_unified_api.c')
        names = ['wmi_unified_vdev_create_send', 'wmi_unified_vdev_start_send',
                 'wmi_unified_pdev_param_send', 'wmi_unified_vdev_set_param_send',
                 'wmi_unified_init_cmd_send']
        bodies = '\n'.join(function(text, n) for n in names)
        self.compile_run(r'''
typedef int QDF_STATUS;
#define QDF_STATUS_E_FAILURE 1
#define QDF_MAC_ADDR_SIZE 6
#define wmi_vdev_param_rx_decap_type 64
struct vdev_create_params { unsigned vdev_id, type, subtype, pdev_id; };
struct vdev_start_params { unsigned vdev_id, is_restart;
 struct { unsigned mhz, phy_mode; } channel; };
struct pdev_params { unsigned param_id, param_value; };
struct vdev_set_params { unsigned vdev_id, param_id, param_value; };
struct resource { unsigned rx_decap_mode, num_vdevs, num_peers; };
struct wmi_init_cmd_param { struct resource *res_cfg; };
struct handle;
typedef struct handle *wmi_unified_t;
struct ops {
 int (*send_vdev_create_cmd)(wmi_unified_t, uint8_t *, struct vdev_create_params *);
 int (*send_vdev_start_cmd)(wmi_unified_t, struct vdev_start_params *);
 int (*send_pdev_param_cmd)(wmi_unified_t, struct pdev_params *, uint8_t);
 int (*send_vdev_set_param_cmd)(wmi_unified_t, struct vdev_set_params *);
 int (*init_cmd_send)(wmi_unified_t, struct wmi_init_cmd_param *);
};
struct handle { struct ops *ops; };
static bool creek_activation_diag = true;
''' + bodies + r'''
static int called;
static int submit(wmi_unified_t h, struct vdev_set_params *p)
{ (void)h; (void)p; called++; return 7; }
int main(void) {
 struct ops ops = {0}; struct handle h = { &ops };
 struct vdev_create_params create = {0};
 struct vdev_start_params start = {0};
 struct pdev_params pdev = {0}; struct vdev_set_params vdev = {0};
 struct resource res = {0}; struct wmi_init_cmd_param init = { &res };
 uint8_t mac[6] = {0};
 assert(wmi_unified_vdev_create_send(&h, mac, &create) == 1);
 assert(wmi_unified_vdev_start_send(&h, &start) == 1);
 assert(wmi_unified_pdev_param_send(&h, &pdev, 0) == 1);
 assert(wmi_unified_vdev_set_param_send(&h, &vdev) == 1);
 assert(wmi_unified_init_cmd_send(&h, &init) == 1);
 ops.send_vdev_set_param_cmd = submit;
 assert(wmi_unified_vdev_set_param_send(&h, &vdev) == 7 && called == 1);
 creek_activation_diag = false;
 assert(wmi_unified_vdev_set_param_send(&h, &vdev) == 7 && called == 2);
 return 0;
}
''')

    def test_counter_accuracy_disable_bounds_and_truncation(self):
        text = source('qcacld-3.0/core/dp/htt/htt_t2h.c')
        helper = text[text.index('#define HTT_DIAG_PATHS'):text.index('/*--- target->host')]
        self.compile_run(r'''
typedef struct { long long value; } atomic64_t;
#define atomic64_read(a) ((a)->value)
#define atomic64_inc_return(a) (++(a)->value)
struct kernel_param { int unused; };
struct kernel_param_ops { int (*get)(char *, const struct kernel_param *); };
struct htt_pdev_t { struct { unsigned is_full_reorder_offload; } cfg; };
typedef unsigned *qdf_nbuf_t;
static unsigned qdf_nbuf_len(qdf_nbuf_t b) { return *b; }
static unsigned cds_get_conparam(void) { return 0; }
static int scnprintf(char *buf, int size, const char *fmt, ...) {
 va_list ap; int n; va_start(ap, fmt); n = vsnprintf(buf, size, fmt, ap);
 va_end(ap); return n >= size ? size - 1 : n;
}
''' + helper + r'''
int main(void) {
 struct htt_pdev_t p = {{1}}; unsigned bytes = 24, i, j;
 char buf[4096]; int n;
 for (i = 0; i < 1024; i++) htt_diag_ingress(2, 18, &p, &bytes);
 assert(htt_diag_counts[2][18].value == 1024);
 ol_rx_diag = false; htt_diag_ingress(2, 18, &p, &bytes);
 assert(htt_diag_counts[2][18].value == 1024);
 ol_rx_diag = true;
 htt_diag_ingress(3, 18, &p, &bytes); htt_diag_ingress(0, 256, &p, &bytes);
 n = htt_diag_counts_get(buf, NULL); assert(n > 0 && n < 4096);
 assert(strstr(buf, "path=2 type=18 count=1024"));
 for (i = 0; i < 3; i++) for (j = 0; j < 256; j++)
  htt_diag_counts[i][j].value = 1;
 n = htt_diag_counts_get(buf, NULL);
 assert(n < 4096 && strstr(buf, "truncated=1"));
 return 0;
}
''')

    def test_dispatch_instrumented_without_parser_override(self):
        text = source('qcacld-3.0/core/dp/htt/htt_t2h.c')
        for path in range(3):
            self.assertEqual(text.count(f'htt_diag_ingress({path}, msg_type'), 1)
        rx = source('qcacld-3.0/core/dp/htt/htt_rx_ll.c')
        self.assertIn('if (cds_get_conparam() == QDF_GLOBAL_MONITOR_MODE)\n'
                      '\t\thtt_rx_amsdu_pop = htt_rx_mon_amsdu_rx_in_order_pop_ll;', rx)
        # Copy observes native output; it must not replace the selected parser.
        self.assertNotIn('ol_monitor_eapol_copy', rx)

    def test_cdp_backend_and_firmware_response_are_separate(self):
        hdd = source('qcacld-3.0/core/hdd/src/wlan_hdd_rx_monitor.c')
        self.assertIn('backend_present=%u', hdd)
        self.assertIn('cmn_drv_ops->txrx_set_monitor_mode', hdd)
        self.assertEqual(hdd.count('ret = cdp_set_monitor_mode(soc, vdev_id, false);'), 1)
        wma = source('qcacld-3.0/core/wma/src/wma_dev_if.c')
        self.assertIn('fw-start-response mode=%u vdev=%u fw_status=%u', wma)
        self.assertNotIn('wma_mon_vdev_stop_wait', source('qcacld-3.0/core/wma/src/wma_utils.c'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
