#ifndef IP_FASTPATH_H
#define IP_FASTPATH_H
#endif

#define MAX_ING_SESSIONS 1024

/* Common IPv4 protocol 8-bit numbers */
#define PROTO_HOPOPT 0
#define PROTO_ICMP 1
#define PROTO_IGMP 2
#define PROTO_GGP 3
#define PROTO_IPINIP 4
#define PROTO_ST 5
#define PROTO_TCP 6
#define PROTO_IGP 9
#define PROTO_UDP 17

/* PM counters */



typedef struct ipv4_ing_session_table{

  uint32_t ipv4_src_adr;
  uint32_t ipv4_dst_adr;
  uint16_t vlan_id;
  uint8_t dscp_bits;
  uint16_t udp_src_port;
  uint16_t udp_dst_port;
   
}ipv4_ing_session_table;

