#ifndef DBG
# define DBG 0
#endif

int printk(const char *format, ...);
#define debug(fmt, ...) if(DBG) { printk("%s:%d %s: " fmt, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); }
#define dump_printk(fmt, ...) if(1) { printk(fmt, ##__VA_ARGS__); }

void jc_test() {
    //printk("TTRT in jc_test\n"); // TCP_STREAM goes from 650 to 32 MBit/s
    //printk(""); // TCP_STREAM goes from 650 to 480 MBit/s
}

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

typedef struct __attribute__((packed)) icmp_frame {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t id;
  uint16_t seq;
  union __attribute__((packed)) {
    uint8_t __data[1500];
  } pp;
} icmp_frame;

void dump_icmp_frame(const icmp_frame* fr) {
  dump_printk("  ICMP: type=%d code=%d checksum=%d id=%d seq=%d\n",
    fr->type, fr->code, local_ntohs(fr->checksum),
    local_ntohs(fr->id), local_ntohs(fr->seq));
  // data - length is determined by ipv4_frame.length
}

typedef struct  __attribute__((packed)) tcp_frame {
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
} tcp_frame;

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

typedef struct __attribute__((packed)) udp_frame {
  uint16_t sport;
  uint16_t dport;
  uint16_t length;
  uint16_t checksum;
  /* data - variable length */
  uint8_t data[1500];
} udp_frame;

void dump_udp_frame(const udp_frame* fr) {
  dump_printk("  UDP: sport=%d dport=%d length=%d checksum=%d\n",
    local_ntohs(fr->sport), local_ntohs(fr->dport), local_ntohs(fr->length), local_ntohs(fr->checksum));
}

typedef struct __attribute__((packed)) ipv4_frame {
  uint8_t version; /* version << 4 | header length */
  uint8_t services;
  uint16_t length;
  uint16_t id;
  uint16_t flags; /* flags << 5 | fragment_offset */
  uint8_t ttl;
  uint8_t proto;
  uint16_t checksum;
  union __attribute__((packed)) {
    uint32_t b32;
    uint8_t b8[4];
  } src_ip;
  union __attribute__((packed)) {
    uint32_t b32;
    uint8_t b8[4];
  } dest_ip;
  union __attribute__((packed)) {
    uint8_t __data[1500];
    icmp_frame icmp;
    udp_frame udp;
    tcp_frame tcp;
  } pp;
} ipv4_frame;

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

typedef struct __attribute__((packed)) arp_frame {
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
} arp_frame;

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

typedef struct __attribute__((packed)) vlan_frame {
  uint16_t prio_dei_id;
  uint16_t type;
  union __attribute__((packed)) {
    uint8_t __data[1500];
    ipv4_frame ipv4;
    arp_frame arp;
  } pp; /* payload */
} vlan_frame;

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

typedef struct __attribute__((packed)) ethernet_frame {
  uint8_t dest_mac[6];
  uint8_t src_mac[6];
  uint16_t type;
  union __attribute__((packed)) {
    uint8_t __data[1500];
    vlan_frame vlan;
    ipv4_frame ipv4;
    arp_frame arp;
  } pp; /* payload */
} ethernet_frame;

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

int vfw_process_arp(arp_frame* fr, int len) {
  return len;
}

/*int vfw_process_ipv4_icmp(icmp_frame* fr, int len) {
  return len;
}

int vfw_process_ipv4_tcp(tcp_frame* fr, int len) {
  return len;
}

int vfw_process_ipv4_udp(udp_frame* fr, int len) {
  return len;
}*/

// 10.77.1.10
// network order
#define IP_FROM_DOTTED(aa, bb, cc, dd) local_htonl((aa)*256*256*256 + (bb)*256*256 + (cc)*256 + (dd))
#define SRV1_IP IP_FROM_DOTTED(10,77,1,10)
#define SRV2_IP IP_FROM_DOTTED(10,77,1,11)
#define TRUSTED_CLIENT1_IP IP_FROM_DOTTED(10,77,2,10)
#define TRUSTED_SUBNET IP_FROM_DOTTED(10,77,2,0)

#define IP_MASK_32 0xFFFFFFFF
#define IP_MASK_24 0x00FFFFFF
#define IP_MASK_16 0x0000FFFF

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_ECHO_REQUEST 8

// IP and port in network order
int header_tcp_match(ipv4_frame *fr,
  uint32_t src_ip,  uint32_t src_mask,  uint16_t sport,
  uint32_t dest_ip, uint32_t dest_mask, uint16_t dport) {
  tcp_frame *tcp_fr = &(fr->pp.tcp);
  if (
    (fr->src_ip.b32 & src_mask) == (src_ip & src_mask) &&
    (fr->dest_ip.b32 & dest_mask) == (dest_ip & dest_mask) &&
    (sport == 0 || tcp_fr->sport == sport) &&
    (dport == 0 || tcp_fr->dport == dport)
    ) {
    return 1;
  }
  return 0;
}

int header_icmp_match(ipv4_frame *fr,
  uint32_t src_ip,  uint32_t src_mask,
  uint32_t dest_ip, uint32_t dest_mask,
  uint8_t type) {
  icmp_frame *icmp_fr = &(fr->pp.icmp);
  if (
    (fr->src_ip.b32 & src_mask) == (src_ip & src_mask) &&
    (fr->dest_ip.b32 & dest_mask) == (dest_ip & dest_mask) &&
    (type == 0xFF || icmp_fr->type == type)
    ) {
    return 1;
  }
  return 0;
}

#define ALLOW_TCP_FROM_ANY(fr, dest_ip, dest_port) \
  { \
    if (header_tcp_match(fr, 0x00000000, 0x00000000, 0,         dest_ip,    IP_MASK_32, dest_port)) return len; \
    if (header_tcp_match(fr, dest_ip,    IP_MASK_32, dest_port, 0x00000000, 0x00000000, 0)) return len; \
  }

#define ALLOW_TCP_FROM_ONE(fr, src_ip, dest_ip, dest_port) \
  { \
    if (header_tcp_match(fr, src_ip,  IP_MASK_32, 0,         dest_ip, IP_MASK_32, dest_port)) return len; \
    if (header_tcp_match(fr, dest_ip, IP_MASK_32, dest_port, src_ip,  IP_MASK_32, 0)) return len; \
  }

#define ALLOW_TCP_FROM_SUBNET(fr, src_ip, src_mask, dest_ip, dest_port) \
  { \
    if (header_tcp_match(fr, src_ip,  src_mask,   0,         dest_ip, IP_MASK_32, dest_port)) return len; \
    if (header_tcp_match(fr, dest_ip, IP_MASK_32, dest_port, src_ip,  src_mask,   0)) return len; \
  }

// sport and dport are at same offset for TCP and UDP
#define header_udp_match header_tcp_match
#define ALLOW_UDP_FROM_ANY ALLOW_TCP_FROM_ANY
#define ALLOW_UDP_FROM_ONE ALLOW_TCP_FROM_ONE
#define ALLOW_UDP_FROM_SUBNET ALLOW_TCP_FROM_SUBNET

int vfw_process_ipv4(ipv4_frame* fr, int len) {
  // return len; - ACCEPT
  // return 0; - DROP
  switch(fr->proto) {
    case IP_PROTO_ICMP:
      // SRV1
      if (header_icmp_match(fr, 0x00000000, 0x00000000, SRV1_IP, IP_MASK_32, ICMP_TYPE_ECHO_REQUEST)) return len;
      if (header_icmp_match(fr, SRV1_IP, IP_MASK_32, 0x00000000, 0x00000000, ICMP_TYPE_ECHO_REPLY)) return len;
      // icmp redirect - drop

      // SRV2
      if (header_icmp_match(fr, 0x00000000, 0x00000000, SRV2_IP, IP_MASK_32, ICMP_TYPE_ECHO_REQUEST)) return len;
      if (header_icmp_match(fr, SRV2_IP, IP_MASK_32, 0x00000000, 0x00000000, ICMP_TYPE_ECHO_REPLY)) return len;
      // icmp redirect - drop
    case IP_PROTO_TCP:
      // SRV1
      ALLOW_TCP_FROM_ANY(fr, SRV1_IP, local_htons(80));
      ALLOW_TCP_FROM_ANY(fr, SRV1_IP, local_htons(81));
      ALLOW_TCP_FROM_ANY(fr, SRV1_IP, local_htons(443));
      ALLOW_TCP_FROM_SUBNET(fr, TRUSTED_SUBNET, IP_MASK_24, SRV1_IP, local_htons(8080));
      ALLOW_TCP_FROM_SUBNET(fr, TRUSTED_SUBNET, IP_MASK_24, SRV1_IP, local_htons(22));
      // tcp port 3333 - drop all
      ALLOW_TCP_FROM_ANY(fr, SRV1_IP, local_htons(12865));
      ALLOW_TCP_FROM_ANY(fr, SRV1_IP, local_htons(12866));
      //ALLOW_TCP_FROM_ONE(fr, TRUSTED_CLIENT1_IP, SRV1_IP, local_htons(12865));
      //ALLOW_TCP_FROM_SUBNET(fr, TRUSTED_SUBNET, IP_MASK_24, SRV1_IP, local_htons(12866));

      // SRV2

      return 0;
    case IP_PROTO_UDP:
      // SRV1

      // SRV2
      ALLOW_UDP_FROM_ANY(fr, SRV2_IP, local_htons(53));
      ALLOW_UDP_FROM_SUBNET(fr, TRUSTED_SUBNET, IP_MASK_24, SRV2_IP, local_htons(123));
      // udp port 3333 - drop

      return 0;
    default:
      return 0;
      break;
  }
  return len;
}

int vfw_process(ethernet_frame* eth_fr, int len) {
  //dump_ethernet_frame(eth_fr);
  // check for min required length
  if(len <= 18) {
    return 0;
  }

  if(local_ntohs(eth_fr->type) != ETH_TYPE_VLAN) {
    return 0;
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
      return 0;
  }

  ipv4_frame  *ipv4_fr = NULL;
  arp_frame *arp_fr = NULL;

  switch(local_ntohs(vlan_fr->type)) {
    case ETH_TYPE_ARP:
        arp_fr = &(vlan_fr->pp.arp);
        len = vfw_process_arp(arp_fr, len);
        break;
    case ETH_TYPE_IPv4:
        ipv4_fr = &(vlan_fr->pp.ipv4);
        len = vfw_process_ipv4(ipv4_fr, len);
        break;
    default:
        //dump_printk("  DROP vlan_fr->type=0x%04x eth_fr=%p vlan_fr=%p\n", local_ntohs(vlan_fr->type), eth_fr, vlan_fr);
        return 0;
        break;
  }

//DONE_FWD:
  vlan_frame_set_tag(vlan_fr, vlan_tag);
  //dump_printk("  FWD new len=%d\n", len);
  return len;
}

/*
OSv - forward betwee two NICs
*/
int vfw_process_osv(ethernet_frame* eth_fr, int len) {
  //dump_ethernet_frame(eth_fr);
  // check for min required length
  if(len <= 18) {
    return 0;
  }

  ipv4_frame  *ipv4_fr = NULL;
  arp_frame *arp_fr = NULL;

  switch(local_ntohs(eth_fr->type)) {
    case ETH_TYPE_ARP:
        arp_fr = &(eth_fr->pp.arp);
        len = vfw_process_arp(arp_fr, len);
        break;
    case ETH_TYPE_IPv4:
        ipv4_fr = &(eth_fr->pp.ipv4);
        len = vfw_process_ipv4(ipv4_fr, len);
        break;
    default:
        //dump_printk("  DROP eth_fr->type=0x%04x eth_fr=%p \n", local_ntohs(eth_fr->type), eth_fr);
        return 0;
        break;
  }

//DONE_FWD:
  //dump_printk("  FWD new len=%d\n", len);
  return len;
}
