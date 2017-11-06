#ifndef IP_FASTPATH_H
#define IP_FASTPATH_H
#endif

#define MAX_ING_SESSIONS 1024
#define MAC_ING_IPIF 8

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
#define PROTO_ESP 50
#define AES_CBC 1
#define HMAC_SHA1 10

/* PM counters */

typedef struct esp_hdr{

  uint32_t spi;
  uint32_t seq_num;
}esp_hdr_t;

typedef struct sad_entry{

  uint32_t spi;
  uint8_t active;
  uint8_t cipher;
  uint8_t auth;
  uint32_t tunnel_src;
  uint32_t tunnel_dst;

}sad_entry_t;

typedef struct ipv4_ipif{
  uint32_t ipv4_dst_adr;
  uint16_t vlan_id;
}ipv4_ipif_t;

typedef struct ipv4_ing_session_table{

  uint32_t ipv4_src_adr; //32
  uint32_t ipv4_dst_adr; //32
  uint16_t vlan_id;
  uint16_t udp_src_port;
  uint16_t udp_dst_port;
   
}ipv4_ing_session_table_t;

typedef struct ipv4_ing_ipif_table{
  ipv4_ipif_t ipif;
}ipv4_ing_ipif_table_t;


