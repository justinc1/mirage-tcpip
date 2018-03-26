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

static inline uint32_t
local_htonl(uint32_t v)
{
  return (((uint32_t)local_htons(v & 0xFFFF)) << 16) | ((uint32_t)local_htons(v >> 16));
}

static inline uint32_t
local_ntohl(uint32_t v)
{
  return local_htonl(v);
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
# define DBG 0
#endif

int printk(const char *format, ...);
#define debug(fmt, ...) if(DBG) { printk("%s:%d %s: " fmt, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); }
#define dump_printk(fmt, ...) if(1) { printk(fmt, ##__VA_ARGS__); }

/*
Very basic ethernet frame C struct;
Ignore possibility of VLAN and other not-most-primitive technologies.
We will try to forward/drop only most basic IP packets.
*/

#define ETH_TYPE_ARP  0x0806
#define ETH_TYPE_IPv4 0x0800
#define ETH_TYPE_VLAN 0x8100
#define ETH_TYPE_IPv6 0x86dd

#define IP_PROTO_ICMP 0x01
#define IP_PROTO_TCP  0x06
#define IP_PROTO_UDP  0x11

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

void dump_icmp_frame(const icmp_frame* fr) {
  dump_printk("  ICMP: type=%d code=%d checksum=%d id=%d seq=%d\n",
    fr->type, fr->code, local_ntohs(fr->checksum),
    local_ntohs(fr->id), local_ntohs(fr->seq));
  // data - length is determined by ipv4_frame.length
}

typedef struct tcp_frame {
  uint16_t sport;
  uint16_t dport;
  uint32_t seq;
  uint32_t ack;
  uint16_t header_len_flags;
  uint16_t window_size;
  uint16_t checksum;
  uint16_t urgent;
  /* options - variable length */
  /* data - variable length */
  uint8_t __var_len_pp[1500];
} tcp_frame __attribute__((packed));

#define tcp_frame_get_header_len(fr) (local_ntohs(fr->header_len_flags) >> 12)
#define tcp_frame_get_flags(fr)      (local_ntohs(fr->header_len_flags) & 0x0FFF)

void dump_tcp_frame(const tcp_frame* fr) {
  dump_printk("  TCP: sport=%d dport=%d\n",
    local_ntohs(fr->sport), local_ntohs(fr->dport) );
  uint16_t header_len = tcp_frame_get_header_len(fr);
  uint16_t flags = tcp_frame_get_flags(fr);
  dump_printk("  TCP: seq=%u ack=%u header_len=%d flags=0x%03x checksum=%d\n",
    local_ntohl(fr->seq), local_ntohl(fr->ack), header_len, flags, local_ntohs(fr->checksum));
}

typedef struct udp_frame {
  uint16_t sport;
  uint16_t dport;
  uint16_t length;
  uint16_t checksum;
  /* data - variable length */
  uint8_t data[1500];
} udp_frame __attribute__((packed));

void dump_udp_frame(const udp_frame* fr) {
  dump_printk("  UDP: sport=%d dport=%d length=%d checksum=%d\n",
    local_ntohs(fr->sport), local_ntohs(fr->dport), local_ntohs(fr->length), local_ntohs(fr->checksum));
}

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
    udp_frame udp;
    tcp_frame tcp;
  } pp  __attribute__((packed));
} ipv4_frame __attribute__((packed));

void dump_ipv4_frame(const ipv4_frame* fr) {
  //printk("  IPv4: &=%p\n", fr);
  dump_printk("  IPv4: version=%d header_len=%d length=%d id=%d\n",
    (fr->version)>>4, (fr->version)&0x0F, local_ntohs(fr->length), local_ntohs(fr->id) );
  dump_printk("  IPv4: ttl=%d proto=%d checksum=%d\n",
    fr->ttl, fr->proto, local_ntohs(fr->checksum) );
  dump_printk("  IPv4: src=%d.%d.%d.%d dest=%d.%d.%d.%d\n",
    fr->src_ip.b8[0], fr->src_ip.b8[1], fr->src_ip.b8[2], fr->src_ip.b8[3],
    fr->dest_ip.b8[0], fr->dest_ip.b8[1], fr->dest_ip.b8[2], fr->dest_ip.b8[3]);
  //dump_printk("  IPv4: &src=%p &dest=%p\n", &(fr->src_ip.b32), &(fr->dest_ip.b32));
  switch (fr->proto) {
    case IP_PROTO_ICMP:
      dump_icmp_frame(&(fr->pp.icmp));
      break;
    case IP_PROTO_TCP:
      dump_tcp_frame(&(fr->pp.tcp));
      break;
    case IP_PROTO_UDP:
      dump_udp_frame(&(fr->pp.udp));
      break;
    default:
      dump_printk("         proto=0x%04x UNKNOWN\n", fr->proto);
      break;
  }
}

typedef struct arp_frame {
  uint16_t hw_type;
  uint16_t proto_type;
  uint8_t hw_size;
  uint8_t proto_size;
  uint16_t opcode;
  /*
  sender_mac [hw_size];
  sender_ip [proto_size];
  target_mac [hw_size];
  target_ip [proto_size];
  payload [];
  */
  uint8_t __var_len_pp[1500];
} arp_frame __attribute__((packed));

#define arp_frame_get_sender_mac(fr) (fr->__var_len_pp)
#define arp_frame_get_sender_ip(fr)  (fr->__var_len_pp + fr->hw_size)
#define arp_frame_get_target_mac(fr) (fr->__var_len_pp + fr->hw_size + fr->proto_size)
#define arp_frame_get_target_ip(fr)  (fr->__var_len_pp + fr->hw_size + fr->proto_size + fr->hw_size)
#define arp_frame_get_payload(fr)    (fr->__var_len_pp + fr->hw_size + fr->proto_size + fr->hw_size + fr->proto_size)

/*
fmt="%02x", arr = [0x11, 0x22, 0x33], sep=":" => print "11:22:33"
*/
void printk_bytes(const char fmt[], const uint8_t* arr, int len, const char sep[]) {
  if(len <= 0) return;
  dump_printk(fmt, arr[0]);
  for (int ii=1; ii<len; ii++) {
    dump_printk(sep);
    dump_printk(fmt, arr[ii]);
  }
}

void dump_arp_frame(const arp_frame* fr) {
  //debug("  VLAN: &=%p\n", fr);
  dump_printk("  ARP: hw_type=%d proto_type=0x%04x hw_size=%d proto_size=%d\n",
    local_ntohs(fr->hw_type), local_ntohs(fr->proto_type), fr->hw_size, fr->proto_size);
  dump_printk("  ARP: sender MAC=");
  printk_bytes("%02x", arp_frame_get_sender_mac(fr), fr->hw_size, ":");
  dump_printk(" IP=");
  printk_bytes("%d", arp_frame_get_sender_ip(fr), fr->proto_size, ".");
  dump_printk("\n");
  dump_printk("  ARP: target MAC=");
  dump_printk("%02x", arp_frame_get_target_mac(fr), fr->hw_size, ":");
  dump_printk(" IP=");
  printk_bytes("%d", arp_frame_get_target_ip(fr), fr->proto_size, ".");
  dump_printk("\n");
}

typedef struct vlan_frame {
  uint16_t prio_dei_id;
  uint16_t type;
  union {
    uint8_t __data[1500];
    ipv4_frame ipv4;
    arp_frame arp;
  } pp __attribute__((packed)); /* payload */
} vlan_frame __attribute__((packed));

#define vlan_frame_get_tag(fr) (local_ntohs(fr->prio_dei_id) & 0x0FFF)
#define vlan_frame_set_tag(fr, tag) (fr->prio_dei_id = local_htons(  (local_ntohs(fr->prio_dei_id) & 0xF000) | (tag & 0x0FFF)  ))

void dump_vlan_frame(const vlan_frame* fr) {
  //dump_printk("  VLAN: &=%p\n", fr);
  dump_printk("  VLAN: tag=%d type=0x%04x\n",
    vlan_frame_get_tag(fr), local_ntohs(fr->type) );
  switch (local_ntohs(fr->type)) {
    case ETH_TYPE_ARP:
      dump_arp_frame(&(fr->pp.arp));
      break;
    case ETH_TYPE_IPv4:
      dump_ipv4_frame(&(fr->pp.ipv4));
      break;
    default:
      dump_printk("         type=0x%04x UNKNOWN\n", local_ntohs(fr->type));
      break;
  }
}

typedef struct ethernet_frame {
  uint8_t dest_mac[6];
  uint8_t src_mac[6];
  uint16_t type;
  union {
    uint8_t __data[1500];
    vlan_frame vlan;
    ipv4_frame ipv4;
    arp_frame arp;
  } pp __attribute__((packed)); /* payload */
} ethernet_frame __attribute__((packed));

void dump_ethernet_frame(const ethernet_frame* fr) {
  dump_printk("  ETHER: &=%p\n", fr);
  dump_printk("  ETHER: src=%02x:%02x:%02x:%02x:%02x:%02x dest=%02x:%02x:%02x:%02x:%02x:%02x\n",
    fr->src_mac[0], fr->src_mac[1], fr->src_mac[2], fr->src_mac[3], fr->src_mac[4], fr->src_mac[5],
    fr->dest_mac[0], fr->dest_mac[1], fr->dest_mac[2], fr->dest_mac[3], fr->dest_mac[4], fr->dest_mac[5]);
  dump_printk("         type=0x%04x \n", local_ntohs(fr->type));
  switch (local_ntohs(fr->type)) {
    case ETH_TYPE_ARP:
      dump_arp_frame(&(fr->pp.arp));
      break;
    case ETH_TYPE_VLAN:
      dump_vlan_frame(&(fr->pp.vlan));
      break;
    case ETH_TYPE_IPv4:
      dump_ipv4_frame(&(fr->pp.ipv4));
      break;
    default:
      dump_printk("         type=0x%04x UNKNOWN\n", local_ntohs(fr->type));
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
  if(len <= 18) {
    CAMLreturn(Val_int(0));
  }

  unsigned char *addr = Caml_ba_data_val(v_ba);
  addr += off;
  ethernet_frame *eth_fr = (ethernet_frame*)(void*)addr;
  dump_ethernet_frame(eth_fr);

  CAMLreturn(Val_int(0));
}

/*
input - ethernt frame
output - modified ehternet frame.
return - 1 if output frame should be forwarded.

Only VLAN tag is changed.
TODO - is in place modification valid?
*/
CAMLprim value
eth_forward_frame(value v_cstruct)
{
  CAMLparam1(v_cstruct);
  CAMLlocal4(v_ba, v_ofs, v_len, v_ret);
  v_ba = Field(v_cstruct, 0);
  v_ofs = Field(v_cstruct, 1);
  v_len = Field(v_cstruct, 2);
  int off = Int_val(v_ofs);
  int len = Int_val(v_len);
  int ret_len = 0;
  debug("ETH frame offset=%d length=%d\n", off, len);
  // check for min required length
  if(len <= 18) {
    CAMLreturn(Val_int(0));
  }

  unsigned char *addr = Caml_ba_data_val(v_ba);
  addr += off;
  ethernet_frame *eth_fr = (ethernet_frame*)(void*)addr;
  //dump_ethernet_frame(eth_fr);
  if(local_ntohs(eth_fr->type) != ETH_TYPE_VLAN) {
    ret_len = 0;
    goto done;
  }
  vlan_frame *vlan_fr = &(eth_fr->pp.vlan);
  uint16_t vlan_tag = vlan_frame_get_tag(vlan_fr);
  switch (vlan_tag) {
    case 10:
      vlan_tag = 11;
      //dump_printk("  FWD vlan 10 to 11\n");
      break;
    case 11:
      vlan_tag = 10;
      //dump_printk("  FWD vlan 11 to 10\n");
      break;
    default:
      // drop other VLANs
      ret_len = 0;
      goto done;
  }

  ret_len = len;
  vlan_frame_set_tag(vlan_fr, vlan_tag);

done:
  v_ret = caml_alloc(3, 0);
  Store_field(v_ret, 0, v_ba); // bi bil lahko tudi prazen ...
  Store_field(v_ret, 1, v_ofs);
  v_len = Val_int(ret_len);
  Store_field(v_ret, 2, v_len);
  CAMLreturn(v_ret);
}


// https://www.linux-nantes.org/~fmonnier/OCaml/ocaml-wrapping-c.html
