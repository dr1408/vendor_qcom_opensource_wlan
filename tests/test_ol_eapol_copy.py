#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile actual validators and RX observer in host stubs. Not a kernel/RF test."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HEADER = ROOT / 'qcacld-3.0/core/dp/txrx/ol_monitor_eapol_validate.h'
SOURCE = ROOT / 'qcacld-3.0/core/dp/txrx/ol_txrx.c'
PRELUDE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <unistd.h>
#define qdf_mem_cmp memcmp
#define qdf_mem_copy memcpy
#define qdf_mem_zero(p,n) memset(p,0,n)
static uint32_t crc32_le(uint32_t crc, const uint8_t *p, size_t n) {
 while(n--) { crc ^= *p++; for(int j=0;j<8;j++) crc=(crc>>1)^((0U-(crc&1))&0xedb88320U); }
 return crc;
}
'''
FIXTURES = r'''
static uint32_t fixture(uint8_t *p, int qos, int ds, int extra) {
 uint32_t h=qos?26:24, body=95+extra;
 memset(p,0,512); p[0]=qos?0x88:0x08; p[1]=ds;
 for(int i=0;i<6;i++){p[4+i]=0x20+i;p[10+i]=0x32+i;p[16+i]=0x44+i;}
 const uint8_t llc[]={0xaa,0xaa,3,0,0,0,0x88,0x8e}; memcpy(p+h,llc,8);
 uint8_t *e=p+h+8; e[0]=1;e[1]=3;e[2]=body>>8;e[3]=body;e[4]=2;
 e[5]=1;e[6]=0x0a;e[97]=extra>>8;e[98]=extra;
 return h+8+4+body;
}
static void ethernet(uint8_t *eth, const uint8_t *raw, uint32_t h, uint32_t n) {
 int ds=raw[1]&3; memcpy(eth,raw+(ds==2?4:16),6);memcpy(eth+6,raw+(ds==2?16:10),6);
 eth[12]=0x88;eth[13]=0x8e;memcpy(eth+14,raw+h+8,n-h-8);
}
'''


class EapolCopy(unittest.TestCase):
    def run_c(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            c, exe = Path(tmp)/'test.c', Path(tmp)/'test'
            c.write_text(PRELUDE + HEADER.read_text() + text)
            subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall',
                            '-Wextra', '-Werror', '-fsanitize=' + os.environ.get('SANITIZERS', 'undefined,bounds'),
                            str(c), '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True)

    def test_raw_eth2_bounds_directions_fcs_and_mismatch(self):
        self.run_c(FIXTURES + r'''
int main(void) {
 uint8_t raw[512],eth[512],backup[512];struct ol_eapol_span s;
 for(int qos=0;qos<2;qos++)for(int ds=1;ds<=2;ds++) {
  uint32_t n=fixture(raw,qos,ds,22),h=qos?26:24;
  memcpy(backup,raw,512);
  assert(ol_eapol_raw(raw,n,&s)==OL_EAPOL_OK && s.mpdu_len==n && s.direction==ds && !s.fcs);
  ethernet(eth,raw,h,n);
  assert(ol_eapol_eth2(raw,64,eth,14+n-h-8,&s)==OL_EAPOL_OK && s.direction==ds);
  assert(!memcmp(raw,backup,512));
  eth[0]^=2;assert(ol_eapol_eth2(raw,64,eth,14+n-h-8,&s)==OL_EAPOL_MISMATCH);eth[0]^=2;
  eth[20]^=1;assert(ol_eapol_eth2(raw,64,eth,14+n-h-8,&s)==OL_EAPOL_MISMATCH);eth[20]^=1;
  uint32_t crc=crc32_le(~0U,raw,n)^~0U;for(int j=0;j<4;j++)raw[n+j]=crc>>(8*j);
  assert(ol_eapol_raw(raw,n+4,&s)==OL_EAPOL_OK && s.fcs && s.mpdu_len==n);
  raw[n]^=1;assert(ol_eapol_raw(raw,n+4,&s)==OL_EAPOL_FCS);
  raw[n]^=1;assert(ol_eapol_raw(raw,n+1,&s)==OL_EAPOL_LENGTH);
  for(uint32_t k=0;k<n;k++)assert(ol_eapol_raw(raw,k,&s)!=OL_EAPOL_OK);
 }
 /* The observed QoS M2 layout: 26+8+4+117=155, optionally four FCS bytes. */
 uint32_t n=fixture(raw,1,1,22);assert(n==155);
 raw[26+8+97] = 1; assert(ol_eapol_raw(raw,n,&s)==OL_EAPOL_LENGTH);
 fixture(raw,1,1,22);raw[1]|=0x40;assert(ol_eapol_raw(raw,n,&s)==OL_EAPOL_HEADER);
 fixture(raw,1,1,22);raw[24]=0x80;assert(ol_eapol_raw(raw,n,&s)==OL_EAPOL_HEADER);
 fixture(raw,1,1,22);raw[22]=1;assert(ol_eapol_raw(raw,n,&s)==OL_EAPOL_HEADER);
 fixture(raw,1,1,22);raw[0]|=1;assert(ol_eapol_raw(raw,n,&s)==OL_EAPOL_HEADER);
 /* Exact-size allocations exercise each bounds check, not padded fixtures. */
 for(uint32_t k=0;k<180;k++) {
  uint8_t *p=malloc(k?k:1); memset(p,0,k); if(k) p[0]=0x88;
  (void)ol_eapol_raw(p,k,&s);(void)ol_eapol_eth2(p,k,p,k,&s); free(p);
 }
 /* Guard pages detect actual boundary reads even when ASan cannot map its
  * shadow region on an Android host. Test each truncated buffer ending
  * exactly at PROT_NONE, including unaligned starts and n=0.
  */
 size_t page=(size_t)sysconf(_SC_PAGESIZE);
 uint8_t *map=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 assert(map!=MAP_FAILED && !mprotect(map+page,page,PROT_NONE));
 uint32_t full=fixture(raw,1,1,22);ethernet(eth,raw,26,full);
 for(uint32_t k=0;k<180;k++) {
  uint8_t *end=map+page-k;
  memcpy(end,raw,k);(void)ol_eapol_raw(end,k,&s);
  (void)ol_eapol_eth2(end,k,eth,14+full-34,&s);
  memcpy(end,eth,k);(void)ol_eapol_eth2(raw,64,end,k,&s);
 }
 assert(!munmap(map,page*2));
 return 0;
}
''')

    def test_observer_ownership_gates_and_private_copy(self):
        text = SOURCE.read_text()
        observer = text[text.index('static bool ol_monitor_eapol_rx;'):
                        text.index('void ol_monitor_mgmt_set_channel(')]
        stubs = r'''
#define READ_ONCE(x) (x)
#define PAGE_SIZE 4096
#define QDF_STATUS_SUCCESS 0
#define QDF_GLOBAL_MONITOR_MODE 4
#define OL_TXRX_PDEV_ID 0
#define wlan_op_mode_monitor 7
#define RX_HTT_HDR_STATUS_LEN 64
#define module_param(...)
#define MODULE_PARM_DESC(...)
#define module_param_cb(name,ops,arg,perm) \
 static const void *use_##name __attribute__((unused))=(ops)
typedef struct {long long value;} atomic64_t;
static void atomic64_inc(atomic64_t *a){a->value++;}
static long long atomic64_read(atomic64_t *a){return a->value;}
struct kernel_param {void *arg;};
struct kernel_param_ops {int (*get)(char*,const struct kernel_param*);};
#define scnprintf snprintf
static void logline(const char *f,...) __attribute__((format(printf,1,2)));
static void logline(const char *f,...){(void)f;}
#define pr_info_ratelimited(...) logline(__VA_ARGS__)
struct htt_host_rx_desc_base {
 struct {uint32_t decap_format;} msdu_start;
 struct {bool msdu_done,fcs_err,mpdu_length_err;} attention;
 struct {bool first_msdu,last_msdu;} msdu_end;
 uint8_t rx_hdr_status[64];
};
struct buf {uint8_t storage[sizeof(struct htt_host_rx_desc_base)+512];uint8_t *data;uint32_t len;bool nonlinear;struct buf *next;};
typedef struct buf *qdf_nbuf_t;
struct cdp_soc_t {int dummy;};
struct ol_txrx_soc_t {int dummy;};
struct ol_txrx_vdev_t {int opmode;int (*rx)(void*,qdf_nbuf_t);void *osif_dev;uint32_t monitor_mgmt_frequency;uint64_t monitor_mgmt_generation;uint8_t vdev_id;struct {int detaching;} delete;};
struct ol_txrx_pdev_t {int peer_ref_mutex;struct ol_txrx_vdev_t *monitor_vdev;};
static struct ol_txrx_vdev_t mon;
static struct ol_txrx_pdev_t pdev;
static int mode, locks, freed, delivered, fail_cb, stale_alloc;
static bool alloc_fail;
static qdf_nbuf_t original;
static uint8_t received[512];static uint32_t received_len;
static int cds_get_conparam(void){return mode;}
static struct ol_txrx_pdev_t *ol_txrx_get_pdev_from_pdev_id(struct ol_txrx_soc_t *s,int id){(void)s;(void)id;return &pdev;}
static void qdf_spin_lock_bh(int *p){(void)p;assert(!locks);locks++;}
static void qdf_spin_unlock_bh(int *p){(void)p;assert(locks==1);locks--;}
static int qdf_atomic_read(int *p){return *p;}
static uint32_t qdf_nbuf_len(qdf_nbuf_t b){return b->len;}
static bool qdf_nbuf_is_nonlinear(qdf_nbuf_t b){return b->nonlinear;}
static uint8_t *qdf_nbuf_data(qdf_nbuf_t b){return b->data;}
static uint8_t *qdf_nbuf_head(qdf_nbuf_t b){return b->storage;}
static struct htt_host_rx_desc_base *htt_rx_desc(qdf_nbuf_t b){return (void*)b->storage;}
static qdf_nbuf_t qdf_nbuf_alloc(void *a,uint32_t n,int h,int align,bool f){
 (void)a;(void)n;(void)h;(void)align;(void)f;if(alloc_fail)return NULL;
 qdf_nbuf_t b=calloc(1,sizeof(*b));assert(b);b->data=b->storage;
 if(stale_alloc) { mon.monitor_mgmt_generation++; }
 return b;
}
static void *qdf_nbuf_put_tail(qdf_nbuf_t b,uint32_t n){b->len=n;return b->data;}
static void qdf_nbuf_set_next(qdf_nbuf_t b,qdf_nbuf_t n){b->next=n;}
static void qdf_nbuf_free(qdf_nbuf_t b){assert(b!=original);freed++;free(b);}
static int callback(void *ctx,qdf_nbuf_t b){
 assert(ctx==&mon && locks==1 && b!=original && !b->next);
 if(fail_cb)return 1;
 assert(b->len<=sizeof(received));memcpy(received,b->data,b->len);received_len=b->len;
 delivered++;qdf_nbuf_free(b);return 0;
}
'''
        self.run_c(stubs + observer + FIXTURES + r'''
int main(void){
 struct ol_txrx_soc_t soc;struct buf b={0};original=&b;
 uint8_t raw[512],saved[sizeof(b.storage)];uint32_t n=fixture(raw,1,1,22);
 b.data=b.storage+sizeof(struct htt_host_rx_desc_base);b.len=n;memcpy(b.data,raw,n);
 struct htt_host_rx_desc_base *d=htt_rx_desc(&b);
 d->msdu_start.decap_format=0;d->attention.msdu_done=true;d->msdu_end.first_msdu=true;d->msdu_end.last_msdu=true;
 /* RAW does not depend on a populated ETH2 captured-header shadow. */
 mon=(struct ol_txrx_vdev_t){.opmode=7,.rx=callback,.osif_dev=&mon,.monitor_mgmt_frequency=2437,.monitor_mgmt_generation=1,.vdev_id=1};pdev.monitor_vdev=&mon;
 memcpy(saved,b.storage,sizeof(saved));
 ol_monitor_eapol_copy((void*)&soc,&b,39);assert(!delivered); /* default off */
 ol_monitor_eapol_rx=true;mode=4;ol_monitor_eapol_copy((void*)&soc,&b,39);assert(!delivered);
 mode=0;ol_monitor_eapol_copy((void*)&soc,&b,39);
 assert(delivered==1 && received_len==8+n && received[2]==8 && !memcmp(received+8,raw,n));
 assert(!memcmp(saved,b.storage,sizeof(saved)) && !locks && !b.next);
 stale_alloc=1;ol_monitor_eapol_copy((void*)&soc,&b,39);assert(delivered==1 && ol_eapol_counts[EC_STALE].value==1);stale_alloc=0;
 fail_cb=1;ol_monitor_eapol_copy((void*)&soc,&b,39);assert(delivered==1 && ol_eapol_counts[EC_CALLBACK].value==1);fail_cb=0;
 alloc_fail=true;ol_monitor_eapol_copy((void*)&soc,&b,39);assert(ol_eapol_counts[EC_ALLOC].value==1);alloc_fail=false;
 mon.delete.detaching=1;ol_monitor_eapol_copy((void*)&soc,&b,39);assert(ol_eapol_counts[EC_NOT_READY].value==1);mon.delete.detaching=0;
 d->msdu_start.decap_format=2;ol_monitor_eapol_copy((void*)&soc,&b,39);assert(ol_eapol_counts[EC_UNSUPPORTED].value==1);
 d->msdu_start.decap_format=3;uint32_t h=26;memcpy(d->rx_hdr_status,raw,64);ethernet(b.data,raw,h,n);b.len=14+n-h-8;
 ol_monitor_eapol_copy((void*)&soc,&b,39);assert(delivered==2 && received_len==8+n && !memcmp(received+8,raw,n));
 assert(!locks && !b.next && freed==4);
 char stats[4096];assert(ol_monitor_eapol_stats_get(stats,NULL)>0 && strstr(stats,"delivered=2"));
 return 0;
}
''')

    def test_hook_order_and_scope(self):
        rx = (ROOT/'qcacld-3.0/core/dp/txrx/ol_rx.c').read_text()
        begin = rx.index('status = htt_rx_amsdu_pop(')
        hook = rx.index('ol_monitor_eapol_copy(', begin)
        discard = rx.index('ol_rx_frames_free(htt_pdev, head_msdu)', hook)
        self.assertLess(begin, hook)
        self.assertLess(hook, discard)
        self.assertIn('observed = qdf_nbuf_next(observed)', rx[begin:discard])
        self.assertIn('!HTT_RX_IN_ORD_PADDR_IND_OFFLOAD_GET', rx[begin:hook])
        self.assertIn('cds_get_conparam() != QDF_GLOBAL_MONITOR_MODE', rx[begin:hook])
        self.assertNotIn('ol_monitor_eapol_copy', (ROOT/'qcacld-3.0/core/dp/htt/htt_rx_ll.c').read_text())

if __name__ == '__main__':
    unittest.main()
