/*
 * Copyright (c) 2010-2011 Anil Madhavapeddy <anil@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdint.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/fail.h>
#include <caml/bigarray.h>

#ifdef __x86_64__

/* WARNING: This code assumes that it is running on a little endian machine (x86) */
static inline uint16_t
local_htons(uint16_t v)
{
  return (((v & 0xFF) << 8) | ((v & 0xFF00) >> 8));
}

static inline uint16_t
local_ntohs(uint16_t v)
{
  return (local_htons(v));
}

static uint16_t
ones_complement_checksum_bigarray(unsigned char *addr, size_t ofs, size_t count, uint64_t sum64)
{
  addr += ofs;
  uint64_t *data64 = (uint64_t *) addr;
  while (count >= 8) {
    uint64_t s = *data64++;
    sum64 += s;
    if (sum64 < s) sum64++;
    count -= 8;
  }

  addr = (unsigned char *) data64;
  while (count > 1) {
    uint16_t v = *((uint16_t *) addr);
    sum64 += v;
    if (sum64 < v) sum64++;
    count -= 2;
    addr += 2;
  }

  if (count > 0) {
    uint16_t v = local_ntohs((*addr) << 8);
    sum64 += v;
    if (sum64 < v) sum64++;
  }

  while (sum64 >> 16)
    sum64 = (sum64 & 0xffff) + (sum64 >> 16);
  return local_htons(~sum64);
}

CAMLprim value
caml_tcpip_ones_complement_checksum(value v_cstruct)
{
  CAMLparam1(v_cstruct);
  CAMLlocal3(v_ba, v_ofs, v_len);
  uint16_t checksum = 0;
  v_ba = Field(v_cstruct, 0);
  v_ofs = Field(v_cstruct, 1);
  v_len = Field(v_cstruct, 2);
  checksum = ones_complement_checksum_bigarray(Caml_ba_data_val(v_ba), Int_val(v_ofs), Int_val(v_len), 0);
  CAMLreturn(Val_int(checksum));
}

/* Checksum a list of cstruct.ts. The complexity of overflow is due to
 * having potentially odd-sized buffers, and the odd byte must be carried
 * forward as 16-byte 1s complement addition if there are more buffers in
 * the chain. */
CAMLprim value
caml_tcpip_ones_complement_checksum_list(value v_cstruct_list)
{
  CAMLparam1(v_cstruct_list);
  CAMLlocal4(v_hd, v_ba, v_ofs, v_len);
  uint16_t checksum = 0;
  uint16_t overflow_val = 0;
  uint16_t overflow = 0;
  size_t count = 0;
  struct caml_ba_array *a = NULL;
  unsigned char *addr;
  uint64_t *data64;
  uint64_t sum64 = 0;
  const size_t sizeof_ll = 8; /* sizeof (uint64_t) */
  while (v_cstruct_list != Val_emptylist) {
    v_hd = Field(v_cstruct_list, 0);
    v_cstruct_list = Field(v_cstruct_list, 1);
    v_ba = Field(v_hd, 0);
    v_ofs = Field(v_hd, 1);
    v_len = Field(v_hd, 2);
    a = Caml_ba_array_val(v_ba);
    addr = a->data + Int_val(v_ofs);
    count = Int_val(v_len);
    if (count <= 0) continue;
    if (overflow != 0) {
      overflow_val = local_ntohs((overflow_val << 8) + (*addr));
      sum64 += overflow_val;
      if (sum64 < overflow_val) sum64++;
      overflow = 0;
      addr++;
      count--;
    }

    data64 = (uint64_t *) addr;

#define checksum_DO_PARTIAL_LOOP_UNROLL
#ifdef checksum_DO_PARTIAL_LOOP_UNROLL
    while (count >= (20 * sizeof_ll)) {
      uint64_t s;

      s = *data64++;
      sum64 += s;
      if (sum64 < s) sum64++;

      s = *data64++;
      sum64 += s;
      if (sum64 < s) sum64++;

      s = *data64++;
      sum64 += s;
      if (sum64 < s) sum64++;

      s = *data64++;
      sum64 += s;
      if (sum64 < s) sum64++;

      s = *data64++;
      sum64 += s;
      if (sum64 < s) sum64++;

      s = *data64++;
      sum64 += s;
      if (sum64 < s) sum64++;

      s = *data64++;
      sum64 += s;
      if (sum64 < s) sum64++;

      s = *data64++;
      sum64 += s;
      if (sum64 < s) sum64++;

      s = *data64++;
      sum64 += s;
      if (sum64 < s) sum64++;

      s = *data64++;
      sum64 += s;
      if (sum64 < s) sum64++;

      s = *data64++;
      sum64 += s;
      if (sum64 < s) sum64++;

      s = *data64++;
      sum64 += s;
      if (sum64 < s) sum64++;

      s = *data64++;
      sum64 += s;
      if (sum64 < s) sum64++;

      s = *data64++;
      sum64 += s;
      if (sum64 < s) sum64++;

      s = *data64++;
      sum64 += s;
      if (sum64 < s) sum64++;

      s = *data64++;
      sum64 += s;
      if (sum64 < s) sum64++;

      s = *data64++;
      sum64 += s;
      if (sum64 < s) sum64++;

      s = *data64++;
      sum64 += s;
      if (sum64 < s) sum64++;

      s = *data64++;
      sum64 += s;
      if (sum64 < s) sum64++;

      s = *data64++;
      sum64 += s;
      if (sum64 < s) sum64++;

      count -= (20 * sizeof_ll);
    }
#endif

    while (count >= sizeof_ll)	{
      uint64_t s = *data64++;
      sum64 += s;
      if (sum64 < s) sum64++;
      count -= sizeof_ll;
    }

    addr = (unsigned char *) data64;
    while (count > 1) {
      uint16_t v = *((uint16_t *) addr);
      sum64 += v;
      if (sum64 < v) sum64++;
      count -= 2;
      addr += 2;
    }

    if (count > 0) {
      overflow_val = *addr;
      overflow = 1;
    }

  }

  if (overflow != 0) {
    overflow_val = local_ntohs(overflow_val << 8);
    sum64 += overflow_val;
    if (sum64 < overflow_val) sum64++;
  }

  while (sum64 >> 16)
    sum64 = (sum64 & 0xffff) + (sum64 >> 16);
  checksum = local_htons(~sum64);
  CAMLreturn(Val_int(checksum));
}

#else		/* Generic implementation */

static uint32_t
checksum_bigarray(unsigned char *addr, size_t ofs, size_t count, uint32_t sum)
{
  addr += ofs;
  while (count > 1) {
    uint16_t v = (*addr << 8) + (*(addr+1));
    sum += v;
    count -= 2;
    addr += 2;
  }
  if (count > 0)
    sum += (*(unsigned char *)addr) << 8;
  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);
  return sum;
}

CAMLprim value
caml_tcpip_ones_complement_checksum(value v_cstruct)
{
  CAMLparam1(v_cstruct);
  CAMLlocal3(v_ba, v_ofs, v_len);
  uint32_t sum = 0;
  uint16_t checksum = 0;
  v_ba = Field(v_cstruct, 0);
  v_ofs = Field(v_cstruct, 1);
  v_len = Field(v_cstruct, 2);
  sum = checksum_bigarray(Caml_ba_data_val(v_ba), Int_val(v_ofs), Int_val(v_len), 0);
  checksum = ~sum;
  CAMLreturn(Val_int(checksum));
}

/* Checksum a list of cstruct.ts. The complexity of overflow is due to
 * having potentially odd-sized buffers, and the odd byte must be carried
 * forward as 16-byte 1s complement addition if there are more buffers in
 * the chain. */
CAMLprim value
caml_tcpip_ones_complement_checksum_list(value v_cstruct_list)
{
  CAMLparam1(v_cstruct_list);
  CAMLlocal4(v_hd, v_ba, v_ofs, v_len);
  uint32_t sum = 0;
  uint16_t checksum = 0;
  uint16_t overflow = 0;
  size_t count = 0;
  struct caml_ba_array *a = NULL;
  unsigned char *addr;
  while (v_cstruct_list != Val_emptylist) {
    v_hd = Field(v_cstruct_list, 0);
    v_cstruct_list = Field(v_cstruct_list, 1);
    v_ba = Field(v_hd, 0);
    v_ofs = Field(v_hd, 1);
    v_len = Field(v_hd, 2);
    a = Caml_ba_array_val(v_ba);
    addr = a->data + Int_val(v_ofs);
    count = Int_val(v_len);
    if (count <= 0) continue;
    if (overflow != 0) {
      sum += (overflow << 8) + (*addr);
      overflow = 0;
      addr++;
      count--;
    }
    while (count > 1) {
      uint16_t v = (*addr << 8) + (*(addr+1));
      sum += v;
      count -= 2;
      addr += 2;
    }
    if (count > 0) {
      if (v_cstruct_list == Val_emptylist)
        sum += (*(unsigned char *)addr) << 8;
      else
        overflow = *addr;
    }
  }
  if (overflow != 0)
    sum += overflow << 8;
  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);
  checksum = ~sum;
  CAMLreturn(Val_int(checksum));
}

#endif

#ifndef DBG
# define DBG 1
#endif

#if DBG
int printk(const char *format, ...);
# define debug(fmt, ...) { printk("%s:%d %s: " fmt, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); }
#else
# define debug(...) /**/
#endif

/*
Very basic ethernet frame C struct;
Ignore possibility of VLAN and other not-most-primitive technologies.
We will try to forward/drop only most basic IP packets.
*/
typedef struct icmp_frame {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t id;
  uint16_t seq;
  union {
    uint8_t __data[1500];
  } pp  __attribute__((packed));
} icmp_frame __attribute__((packed));

typedef struct ipv4_frame {
  uint8_t version; /* version << 4 | header length */
  uint8_t services;
  uint16_t length;
  uint16_t id;
  uint16_t flags; /* flags << 5 | fragment_offset */
  uint8_t ttl;
  uint8_t proto;
  uint16_t checksum;
  union {
    uint32_t b32;
    uint8_t b8[4];
  } src_ip  __attribute__((packed));
  union {
    uint32_t b32;
    uint8_t b8[4];
  } dest_ip  __attribute__((packed));
  union {
    uint8_t __data[1500];
    icmp_frame icmp;
    //udp_frame udp;
    //tcp_frame tcp;
  } pp  __attribute__((packed));
} ipv4_frame __attribute__((packed));

void dump_ipv4_frame(const ipv4_frame* fr) {
  //printk("  IPv4: &=%p\n", fr);
  printk("  IPv4: version=%d header_len=%d length=%d id=%d\n",
    (fr->version)>>4, (fr->version)&0x0F, local_ntohs(fr->length), local_ntohs(fr->id) );
  printk("  IPv4: ttl=%d proto=%d checksum=%d\n",
    fr->ttl, fr->proto, local_ntohs(fr->checksum) );
  printk("  IPv4: src=%d.%d.%d.%d dest=%d.%d.%d.%d\n",
    fr->src_ip.b8[0], fr->src_ip.b8[1], fr->src_ip.b8[2], fr->src_ip.b8[3],
    fr->dest_ip.b8[0], fr->dest_ip.b8[1], fr->dest_ip.b8[2], fr->dest_ip.b8[3]);
  //printk("  IPv4: &src=%p &dest=%p\n", &(fr->src_ip.b32), &(fr->dest_ip.b32));
}

typedef struct ethernet_frame {
  uint8_t dest_mac[6];
  uint8_t src_mac[6];
  uint16_t type;
  union {
    uint8_t __data[1500];
    ipv4_frame ipv4;
    //arp_frame arp;
  } pp __attribute__((packed)); /* payload */
} ethernet_frame __attribute__((packed));

#define ETH_TYPE_ARP  0x0806
#define ETH_TYPE_IPv4 0x0800
#define ETH_TYPE_IPv6 0x86dd

void dump_ethernet_frame(const ethernet_frame* fr) {
  printk("  ETHER: &=%p\n", fr);
  printk("  ETHER: src=%02x:%02x:%02x:%02x:%02x:%02x dest=%02x:%02x:%02x:%02x:%02x:%02x\n",
    fr->src_mac[0], fr->src_mac[1], fr->src_mac[2], fr->src_mac[3], fr->src_mac[4], fr->src_mac[5],
    fr->dest_mac[0], fr->dest_mac[1], fr->dest_mac[2], fr->dest_mac[3], fr->dest_mac[4], fr->dest_mac[5]);
  printk("         type=%04x \n", local_ntohs(fr->type));
  switch (local_ntohs(fr->type)) {
    case ETH_TYPE_ARP:
      break;
    case ETH_TYPE_IPv4:
      dump_ipv4_frame(&(fr->pp.ipv4));
      break;
    default:
      break;
  }
}

CAMLprim value
eth_dump_frame(value v_cstruct)
{
  CAMLparam1(v_cstruct);
  CAMLlocal3(v_ba, v_ofs, v_len);
  v_ba = Field(v_cstruct, 0);
  v_ofs = Field(v_cstruct, 1);
  v_len = Field(v_cstruct, 2);
  int off = Int_val(v_ofs);
  int len = Int_val(v_len);
  debug("ETH frame offset=%d length=%d\n", off, len);

  unsigned char *addr = Caml_ba_data_val(v_ba);
  addr += off;
  ethernet_frame *eth_fr = (ethernet_frame*)(void*)addr;
  dump_ethernet_frame(eth_fr);

  CAMLreturn(Val_int(0));
}
