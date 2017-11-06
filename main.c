
/* Fast Path packet processing prototype 

   see also: ip_fastpath.h

   sven.s.stenstrom@ericsson.com

 */

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_table.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_acl.h>
#include <rte_common.h>
#include <rte_ip_frag.h>

#include <rte_ether.h>
#include <rte_debug.h>

#include "ip_fastpath.h"


uint32_t packets_discarded = 0; //counter to count discarded packets

#define PROMISCIOUS_MODE 0

#define DUMP_PACKET 1

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191 // number of memory buffers allocated
#define MBUF_CACHE_SIZE 250 // size of each memory buffer in bytes
#define BURST_SIZE 32
#define MAX_PKT_BURST 32

#define LOCAL_DMAC_ADR 0x080027f152c2
#define DMAC_MASK_BYTE_0 0xFF0000000000
#define DMAC_MASK_BYTE_1 0x00FF00000000
#define DMAC_MASK_BYTE_2 0x0000FF000000
#define DMAC_MASK_BYTE_3 0x000000FF0000
#define DMAC_MASK_BYTE_4 0x00000000FF00
#define DMAC_MASK_BYTE_5 0x0000000000FF

#define DEFAULT_HASH_FUNC rte_jhash

#define MORE_FRAGMENTS(X) ((X&0x4)>>2)
#define DONT_FRAGMENT(X) ((X&0x2)>>3)

static const struct lcore_conf{

  uint16_t nb_rx_queue;
  uint16_t nb_tx_queue;
  uint16_t socket_id;
  uint16_t lcore_id;
  struct rte_ip_frag_death_row death_row;
  
 
};

static const struct rte_eth_conf port_conf_default = {
  .rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};

struct ipv4_hdr *iph;

static const unsigned short packet_data[64]={0,1,2,3,
					     4,5,6,7,
					     8,9,10,11,
					     12,13,14,15,
					     16,17,18,19,
					     20,21,22,23,
					     24,25,26,27,
					     28,29,30,
					     31,32,33,34,
					     35,36,37,38,
					     39,40,41,42,
					     43,44,45,46,
					     47,48,49,50,
					     51,52,53,54,
					     55,56,57,58,
					     59,60,61,62,63};


struct rte_hash *hash;
struct rte_hash_parameters params;

struct ipv4_5tuple{

  uint8_t proto;
  uint32_t ip_src;
  uint32_t ip_dst;
  uint16_t port_src;
  uint16_t port_dst;
  
};

enum{
  PROTO_FIELD_IPV4,
  SRC_FIELD_IPV4,
  DST_FIELD_IPV4,
  SRCP_FIELD_IPV4,
  DSTP_FIELD_IPV4,
  NUM_FIELDS_IPV4
};

enum{
  RTE_ACL_IPV4VLAN_PROTO,
  RTE_ACL_IPV4VLAN_VLAN,
  RTE_ACL_IPV4VLAN_SRC,
  RTE_ACL_IPV4VLAN_DST,
  RTE_ACL_IPV4VLAN_PORTS,
  RTE_ACL_IPV4VLAN_NUM
};

static uint32_t max_flow_num = 100;

#if 0
struct lcore_queue_conf {
	uint16_t n_rx_queue;
	struct rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
	uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
	struct rte_ip_frag_death_row death_row;
	struct mbuf_table *tx_mbufs[RTE_MAX_ETHPORTS];
	struct tx_lcore_stat tx_stat;
} __rte_cache_aligned;
static struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];
#endif

#define MAX_REASSEMBLY_FLOWS 10
#define MAX_REASSEMBLY_FRAGMENTS 2
#define REASSEMBLY_TIMER_MS 100
#define MAX_SAD 512

//list of mbufs to be transmitted
struct mbuf_table {
	uint32_t len;
	uint32_t head;
	uint32_t tail;
	struct rte_mbuf *m_table[0];
};

struct rte_ip_frag_tbl *frag_table;
struct rte_ip_frag_death_row death_row;
struct mbuf_table *tx_mbufs;

ipv4_ing_session_table_t ing_session[MAX_ING_SESSIONS];

struct rte_acl_field_def ipv4_defs[NUM_FIELDS_IPV4] = {
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint8_t),
		.field_index = 0,
		.input_index = 0,
		.offset = 10, //offsetof(struct ipv4_5tuple, proto), //offset of data into databuffer
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = 1,
		.input_index = 1,
		.offset = 12, //offsetof(struct ipv4_5tuple, ip_src),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = 2,
		.input_index = 2,
		.offset = 16, //offsetof(struct ipv4_5tuple, ip_dst),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = 3,
		.input_index = 3,
		.offset = offsetof(struct ipv4_5tuple, port_src),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = 4,
		.input_index = 3,
		.offset = offsetof(struct ipv4_5tuple, port_dst),
	},
};

RTE_ACL_RULE_DEF(acl4_rule, RTE_DIM(ipv4_defs));

  struct rte_acl_ctx *acx;
  struct rte_acl_config cfg;

static int lcore_ready(__attribute__((unused)) void *arg)
{
	unsigned lcore_id;
	lcore_id = rte_lcore_id();
	if (lcore_id == rte_get_master_lcore())
	  printf("master core %u ready\n", lcore_id);
	else
	  printf("slave core %u ready\n", lcore_id);
	return 0;
}


static inline int port_init(uint8_t port, struct rte_mempool *mbuf_pool){
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;


	if (port >= rte_eth_dev_count())
		return -1;

	/* configure ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	/* allocate and set up 1 RX queue per port */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/*  set up 1 TX queue per port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	/* start port */
	if (rte_eth_dev_start(port)  < 0)
	  return retval;

	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* set promiscious mode */
	rte_eth_promiscuous_enable(port);
	
	return 0;
}


void print_dmac_adr(struct ether_hdr *eth_hdr){


    printf("%x %x %x %x %x %x\n", eth_hdr->d_addr.addr_bytes[0], eth_hdr->d_addr.addr_bytes[1], eth_hdr->d_addr.addr_bytes[2],eth_hdr->d_addr.addr_bytes[3], eth_hdr->d_addr.addr_bytes[4],eth_hdr->d_addr.addr_bytes[5]);

    

}
const void print_smac_adr(struct ether_hdr *eth_hdr){


    printf("%x %x %x %x %x %x\n", eth_hdr->s_addr.addr_bytes[0], eth_hdr->s_addr.addr_bytes[1], eth_hdr->s_addr.addr_bytes[2],eth_hdr->s_addr.addr_bytes[3], eth_hdr->s_addr.addr_bytes[4],eth_hdr->s_addr.addr_bytes[5]);


}

const int match_dmac_adr(struct ether_hdr *eth_hdr){

  if (PROMISCIOUS_MODE)
    return(1);
  
  if (eth_hdr->d_addr.addr_bytes[0] == ((LOCAL_DMAC_ADR & DMAC_MASK_BYTE_0) >> 40) &&
      eth_hdr->d_addr.addr_bytes[1] == ((LOCAL_DMAC_ADR & DMAC_MASK_BYTE_1) >> 32) &&
      eth_hdr->d_addr.addr_bytes[2] == ((LOCAL_DMAC_ADR & DMAC_MASK_BYTE_2) >> 24) &&  
      eth_hdr->d_addr.addr_bytes[3] == ((LOCAL_DMAC_ADR & DMAC_MASK_BYTE_3) >> 16) &&
      eth_hdr->d_addr.addr_bytes[4] == ((LOCAL_DMAC_ADR & DMAC_MASK_BYTE_4) >> 8) &&
      eth_hdr->d_addr.addr_bytes[5] == ((LOCAL_DMAC_ADR & DMAC_MASK_BYTE_5) >> 0)){
    printf("D_MAC match\n");
    return(1);
  }
  
  else{
    printf("D_MAC mismatch, discarding ...\n");
    return(-1);
  }
 
 
}

/* IPv4 session table hash lookup */
inline uint32_t ipv4_session_lookup(uint32_t ipv4_src_adr, uint32_t ipv4_dst_adr, uint16_t udp_src_port, uint16_t udp_dst_port, uint16_t vlan_id){

  uint32_t data;
  uint32_t ret;
  uint32_t key_swapped;
  uint32_t key_temp;
  uint32_t adr_swapped;
  uint32_t key;
  ipv4_ing_session_table_t session;

  session.ipv4_src_adr = ipv4_src_adr;
  session.ipv4_dst_adr = ipv4_dst_adr;
  session.udp_src_port = udp_src_port;
  session.udp_dst_port = udp_dst_port;
  session.vlan_id = vlan_id;
  
  //  adr_swapped = rte_bswap32(adr);
  
  key = rte_jhash(&session, sizeof(ipv4_ing_session_table_t), 123);
  
  printf("searching for key = 0x%08x\n", key);
  
  ret = rte_hash_lookup_data(hash, &key, &data);
  
  if (ret < 0){
    if (ret == ENOENT){
      fprintf(stderr, "no hash entry found\n");
      return 0;
    }
    if (ret == EINVAL){
      fprintf(stderr, "invalid hash parameter\n");
      return 0;
    }
    fprintf(stderr, "no match\n");
    return 0;
  }
  
  return data;
}

/* dump packet to screen */
void hex_dump(char *desc, void *addr, int len){

  int i;
  unsigned char buff[17];
  unsigned char *pc = (unsigned char *)addr;

  if (desc != NULL)
    printf("%s: \n", desc);

  if (len == 0){
    printf(" ZERO LENGTH\n");
    return;
  }

  if (len < 0){
    printf(" NEGATIVE LENGTH\n");
    return;
  }

  for (i=0; i<len;i++){
    if ((i%16)==0){
      if (i != 0)
	printf(" %s\n", buff);
      printf(" %04x ",i);
    }

    printf(" %02x", pc[i]);

    if ((pc[i] < 0x20) || (pc[i] > 0x7e))
      buff[i%16] = '.';
    else
      buff[i%16] = pc[i];
    buff[(i%16)+1] = '\0';
	 
  }
      
  while ((i%16)!=0){
    printf(" ");
    i++;
  }

  printf(" %s\n", buff);
      
  
}

/* Setup ACL table for incoming packets */
static int acl_setup(void){

  int ret;

  RTE_ACL_RULE_DEF(acl_ipv4_rule, RTE_DIM(ipv4_defs));

  struct rte_acl_param prm = {
    .name = "fastpath ACL",
    .socket_id = SOCKET_ID_ANY,
    .rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv4_defs)),
    .max_rule_num = 8,
  };

  struct acl_ipv4_rule acl_rules[] = {

    {
      .data = {.userdata = 1, .category_mask = 1, .priority = 1},
      .field[2] ={.value.u32 = IPv4(192,168,0,0),. mask_range.u32 = 32,},
      .field[3] ={.value.u16 = 0, .mask_range.u32 = 0xffff,},
      .field[4] ={.value.u16 = 0, .mask_range.u32 = 0xffff,},
    },

    {
      .data = {.userdata = 2, .category_mask = 1, .priority = 2},
      .field[2] ={.value.u32 = IPv4(192,168,1,0),. mask_range.u32 = 24,},
      .field[3] ={.value.u16 = 0, .mask_range.u32 = 0xffff,},
      .field[4] ={.value.u16 = 0, .mask_range.u32 = 0xffff,},
    },

    {
      .data = {.userdata = 3, .category_mask = 1, .priority = 3},
      .field[2] ={.value.u32 = IPv4(10,1,1,1), .mask_range.u32 = 32,},
      .field[3] ={.value.u16 = 0, .mask_range.u32 = 0xffff,},
      .field[4] ={.value.u16 = 0, .mask_range.u32 = 0xffff,},
    },
  };
  fflush(stdout);
  printf("Creating ACL context\n");

  /* create ACL context */

  acx = rte_acl_create(&prm);
  if (acx == NULL){
    fprintf(stderr, "Cannot create ACL context\n");
    return -1;
  }
  
  /* add ACL rules to context */

  printf("Adding ACL rules\n");
  
  ret = rte_acl_add_rules(acx, acl_rules, RTE_DIM(acl_rules));
  if (ret != 0){
    fprintf(stderr, "Error adding ACL rules\n");
    return -1;
    
  }

  cfg.num_categories = 1;
  cfg.num_fields = RTE_DIM(ipv4_defs);
  memcpy(cfg.defs, ipv4_defs, sizeof(ipv4_defs));

  printf("Building ACL\n");
  
  ret = rte_acl_build(acx, &cfg);
  if (ret !=0){
    fprintf(stderr, "Cannot build ACL\n");
    return -1;
  }

  return 0;
  
}

/* setup a session table (jhash table) containing <ipv4_src> <ipv4_dst> <vlan_id> <udp_src> <udp_dst> */
static void setup_session_table(void){


	unsigned int d;
	unsigned int key=0;
	
	bzero(&params, sizeof(params));
	params.name = NULL;
	params.entries = 500;
	params.key_len = 4;  //sizeof min tabellstrukt
	params.hash_func = rte_jhash;
	params.hash_func_init_val = 0;

	hash = rte_hash_create(&params);
	printf("**** %d \n", NUM_FIELDS_IPV4);

	if (!hash){
	  fprintf(stderr, "Error creating hash table\n");
	  return;
	}

	/* add a few table entries */
	printf("Populating session table\n");

	ing_session[0].ipv4_src_adr = 0xc0a80a0a;
	ing_session[0].ipv4_dst_adr = 0x0a0a0a0a;
	ing_session[0].vlan_id = 0;
	ing_session[0].udp_src_port = 10;
	ing_session[0].udp_dst_port = 11;

	ing_session[1].ipv4_src_adr = 0xc0a80a0b;
	ing_session[1].ipv4_dst_adr = 0x0b0b0b0b;
	ing_session[1].vlan_id = 0;
	ing_session[1].udp_src_port = 20;
	ing_session[1].udp_dst_port = 21;

	ing_session[2].ipv4_src_adr = 0x01010101;
	ing_session[2].ipv4_dst_adr = 0x0a010101;
	ing_session[2].vlan_id = 0;
	ing_session[2].udp_src_port = 30;
	ing_session[2].udp_dst_port = 11; 

	key = rte_jhash(&ing_session[0], sizeof(ipv4_ing_session_table_t), 123);
	d = 1;
	rte_hash_add_key_data(hash, &key, (void *) (long) d);
	printf("Added hash key = 0x%08x\n", key);

	key = rte_jhash(&ing_session[1],sizeof(ipv4_ing_session_table_t), 123);
	d = 2;
	rte_hash_add_key_data(hash, &key, (void *) (long) d);
	printf("Added hash key = 0x%08x\n", key);

	key = rte_jhash(&ing_session[2],sizeof(ipv4_ing_session_table_t), 123);
	d = 3;
       	rte_hash_add_key_data(hash, &key, (void *) (long) d);
	printf("Added hash key = 0x%08x\n", key);

}

void print_ethaddr(const char *name, const struct ether_addr *eth_addr){
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}

/* Setup IPv4 reassembly context table */
struct rte_ip_frag_tbl *setup_reassembly_table(void){


  uint32_t max_flow_ttl = REASSEMBLY_TIMER_MS;
  uint64_t frag_cycles;


  frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S *
    max_flow_ttl;
  
  frag_table = rte_ip_frag_table_create(MAX_REASSEMBLY_FLOWS, MAX_REASSEMBLY_FRAGMENTS, MAX_REASSEMBLY_FLOWS * MAX_REASSEMBLY_FRAGMENTS, frag_cycles, SOCKET_ID_ANY);

  return frag_table;
  
}

/* IPv4 packet reassembly */
static inline struct rte_mbuf *reassemble(struct rte_mbuf *m, uint8_t portid, uint64_t tms){

  struct ether_hdr *eth_hdr;
  struct rte_ip_frag_tbl *tbl;
  struct rte_ip_frag_death_row *dr;
  struct rx_queue *rxq;
  void *d_addr_bytes;
  uint32_t next_hop;
  uint8_t dst_port;
  
  eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
  
  dst_port = portid;
  
  struct ipv4_hdr *ip_hdr;
  uint32_t ip_dst;
  
  ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
  
  struct rte_mbuf *mo;
  
  tbl = frag_table;
  
  /* prepare mbuf */
  m->l2_len = sizeof(*eth_hdr);
  m->l3_len = sizeof(*ip_hdr);
  
  /* process fragment. */
  mo = rte_ipv4_frag_reassemble_packet(tbl, &death_row, m, tms, ip_hdr);
  if (mo == NULL)
    /* no packet to send out. */
    return NULL;
  
  /* reassembly complete. */
  if (mo != m) {
    m = mo;
    eth_hdr = rte_pktmbuf_mtod(m,
			       struct ether_hdr *);
    ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
    return m;
  }
  
  
}
/* send burst of packets, hard coded this to port 1 for now ... */
static inline uint32_t tx_burst(uint32_t thresh, uint8_t port){
  
  uint32_t fill, len, k, n;
  struct mbuf_table *txmb;
  
  txmb = tx_mbufs;
  len = txmb->len;
  
  if ((int32_t)(fill = txmb->head - txmb->tail) < 0)
    fill += len;
  printf("tx_burst: fill  = %d\n", fill);
  
  if (fill >= thresh) {
    n = RTE_MIN(len - txmb->tail, fill);
    
    k = rte_eth_tx_burst(port, 0, txmb->m_table + txmb->tail, (uint16_t)n); // send burst of n packets on port 1
    
    fill -= k;
    if ((txmb->tail += k) == len)
      txmb->tail = 0;
  }
  
  return fill;
}


/* enqueue a single packet, and send burst if queue is filled */
static inline int enqueue_tx_single_packet(struct rte_mbuf *m, uint8_t port)
{
	uint32_t fill, lcore_id, len;
	struct lcore_queue_conf *qconf;
	struct mbuf_table *txmb;

	txmb = tx_mbufs;
	len = txmb->len;

	fill = tx_burst(MAX_PKT_BURST, port);
	printf("enqueue packet, fill  = %d\n", fill);

	if (fill == len - 1) {
		rte_pktmbuf_free(txmb->m_table[txmb->tail]);
		if (++txmb->tail == len)
			txmb->tail = 0;
	}

	txmb->m_table[txmb->head] = m;
	if(++txmb->head == len)
		txmb->head = 0;

	return 0;
}

/* other stuff to do when discarding packets .. ? */
inline static void discard_packet(struct rte_mbuf *mb){

  packets_discarded++;
  rte_pktmbuf_free(mb);

}


/* todo: lots of cleanup and add conditional debug prints ... */
static __attribute__((noreturn)) void lcore_main(void){
  
  const uint8_t nb_ports = rte_eth_dev_count();
  uint8_t port;
  int packets_rec=0;
  struct ether_hdr *eth_hdr;
  struct ipv4_hdr *ipv4_hdr;
  struct udp_hdr *udp_hdr;
  uint32_t session_ret;
  
  unsigned char *dump_adr;
  void *data;
  
  uint64_t diff_tsc, cur_tsc, prev_tsc;
  
  int ret;
  int adr;
  static int keytest;
  uint16_t udp_dst_port;
  uint16_t udp_src_port;
  uint16_t ipv4_cksum;
  uint16_t frag_offset;
  uint8_t ip_flags; // 0 reserved (0), 1 dont fragment, 2 more fragments
  uint32_t packets_left=0;
  struct mbuf_table *tx_bufs[BURST_SIZE];
  
  struct rte_mbuf *rm;
  
  if (acl_setup() !=0){
    printf("Was unable to run acl_setup()\n");
    exit(0);
  }
  
  setup_session_table();
  
  setup_reassembly_table();
  if (frag_table == NULL){
    fprintf(stderr, "Cannot initialize IP fragmentation table, exiting ...\n");
    exit(0);
  }
  

  
  for (port = 0; port < nb_ports; port++)
    if (rte_eth_dev_socket_id(port) > 0 &&
	rte_eth_dev_socket_id(port) !=
	(int)rte_socket_id())
      printf("note: NUMA node is remote relative to "
	     "polling thread\n", port);
  
  /* main loop, master core (no other cores used ...) */
  for (;;) {
    
    /* Get burst of packets */
    struct rte_mbuf *bufs[BURST_SIZE];
    const uint16_t nb_rx = rte_eth_rx_burst(1, 0, bufs, BURST_SIZE);
    
    if (nb_rx != 0){
      for (packets_left = 0; packets_left<nb_rx; packets_left++){
	printf("PACKETS LEFT = %d\n", nb_rx - packets_left);
	//	    if (nb_rx != 0){
	printf("---\n");
	printf("nb_rx = %d\n", nb_rx);
	
	//eth_hdr = rte_pktmbuf_mtod(bufs[nb_rx-1], struct ether_hdr *);
	eth_hdr = rte_pktmbuf_mtod(bufs[packets_left], struct ether_hdr *);
	if (DUMP_PACKET){}
	//  hex_dump("packet dump", eth_hdr, 40);
	
	
	printf("packet received with ether type = 0x%04x\n", eth_hdr->ether_type);
	printf("packet received from MAC address ");
	print_smac_adr(eth_hdr);
	printf("destination MAC address ");
	print_dmac_adr(eth_hdr);
	//	      if (match_dmac_adr(eth_hdr)!=1){ //discard if no dmac match
	//		rte_pktmbuf_free(bufs[nb_rx-1]);
	//		break;
	//	      }
	
	if (rte_bswap16(eth_hdr->ether_type) == ETHER_TYPE_IPv4){
	  ipv4_hdr = eth_hdr+1; // point to beginning of IPv4 header
	  
	  printf("IPv4 total length = %d\n",rte_bswap16(ipv4_hdr->total_length));
	  
	  /* Ip reassembly */
	  
	  cur_tsc = rte_rdtsc(); //get current time
	  
	  /* ACL */
	  
	  uint32_t acl_result=0;
	  hex_dump("packet dump", ipv4_hdr, 20);
	  printf("IP Packet received, running ACL\n");
	  rte_acl_classify(acx, (uint8_t **)&ipv4_hdr, &acl_result, 1, 1);
	  printf("**** ACL results: %d\n", acl_result);//, acl_result[1], acl_result[2], acl_result[3]);     
	  
	  printf("IPv4 dest address 0x%08x\n", rte_bswap32(ipv4_hdr->dst_addr));
	  
	  printf("IPv4 source address 0x%08x\n", rte_bswap32(ipv4_hdr->src_addr));
	  if (ipv4_hdr->next_proto_id == PROTO_UDP){
	    printf("Encapsulated protocol is UDP\n");
	    udp_hdr = ipv4_hdr+1; // point to beginning of UDP header
	    printf("UDP dest port %d\n",rte_bswap16(udp_hdr->dst_port));
	    printf("UDP source port %d\n", rte_bswap16(udp_hdr->src_port));
		    
	    session_ret = ipv4_session_lookup(rte_bswap32(ipv4_hdr->src_addr), rte_bswap32(ipv4_hdr->dst_addr), rte_bswap16(udp_hdr->src_port), rte_bswap16(udp_hdr->dst_port), 0);
	    if (session_ret !=0){
	      printf("IPv4 session found, data = 0x%08x\n", session_ret);
	    }
	    else
	      printf("IPv4 session not found \n");
	    
	  }
	  
	  if (ipv4_hdr->next_proto_id == PROTO_ESP){
	    printf("ESP encapsulation\n");

	    esp_hdr_t *esp_hdr; 
	    uint32_t spi;
	    sad_entry_t sad[MAX_SAD];
	    uint8_t sa_mismatch=0;
	    
	    sad[0].active = 1;
	    sad[0].spi = 1;
	    sad[0].cipher = AES_CBC;
	    sad[0].auth = HMAC_SHA1;
	    sad[0].tunnel_src = IPv4(1,1,1,1);
	    sad[0].tunnel_dst = IPv4(2,2,2,2);
	    sad[1].active = 1;
	    sad[1].spi = 2;
	    sad[1].cipher = AES_CBC;
	    sad[1].auth = HMAC_SHA1;
	    sad[1].tunnel_src = IPv4(11,11,11,11);
	    sad[1].tunnel_dst = IPv4(2,2,2,2);
	    
	    sad[2].active = 1;
	    sad[2].spi = 3;
	    sad[2].cipher = AES_CBC;
	    sad[2].auth = HMAC_SHA1;
	    sad[2].tunnel_src = IPv4(111,111,111,111);
	    sad[2].tunnel_dst = IPv4(2,2,2,2);
	    
	    esp_hdr = ipv4_hdr+1;
	    
	    /* SPD and SA lookup */
	    // SPD implemented as ACL, SAD implemented as array table
	    
	    if (sad[esp_hdr->spi].active){
	      
	      if (ipv4_hdr->src_addr != sad[esp_hdr->spi].tunnel_src)
		sa_mismatch = 1;
	      
	      if (ipv4_hdr->dst_addr != sad[esp_hdr->spi].tunnel_dst && !sa_mismatch)
		break;
	      // verify that tunnel adresses match packet
	      
	    }
	  }
	  
	  if (ipv4_hdr->next_proto_id == PROTO_ICMP)
	    printf("IP packet contains ICMP\n");
	  
	  ipv4_cksum = ipv4_hdr->hdr_checksum;
	  ipv4_hdr->hdr_checksum = 0;
	  if (ipv4_cksum != rte_ipv4_cksum(ipv4_hdr))
	    printf("corrupt IPv4 checksum detected\n");
	  else
	    printf("IPv4 checksum correct\n");
	  
	  /* check for IP fragment */
	  
	  if (rte_ipv4_frag_pkt_is_fragmented(ipv4_hdr) == 0)
	    printf("Packet is not fragmented\n");
	  else{
	    printf("Packet is fragmented\n");
	    rm = reassemble(bufs[packets_left], 0, cur_tsc);
	    if (rm == NULL)
	      printf("packet reassembly not completed for this packet\n");
	    else{
	      printf("packet reassembly was completed for this packet\n");
	      enqueue_tx_single_packet(rm, 1); // queue rm to port 1 for transmission
	    }
	    
	  }
	  
	}
	
	else
	  printf("Packet type is not IPv4\n");
	
      }
      
      if (packets_left == 0)
	continue;
      

      tx_burst(1, 1); // thres = 1, port = 1
      rte_ip_frag_free_death_row(&death_row,1);
	

      printf("burst of packets sent, waiting for more ...\n");
    } 
  }
}

/* ******************************************************************************************************************************/
int main(int argc, char **argv){

  int ret;
  unsigned lcore_id;
  unsigned master_core_id;
  struct rte_eth_conf port_conf = port_conf_default; // structure containing ethernet port configuration & options, not currently used
  const uint16_t rx_rings = 1, tx_rings = 1; // number of transmit and receive rings
  unsigned nb_ports=2;
  struct rte_mempool *mbuf_pool;
  int portid;
  struct rte_mbuf *mbuf;
  void *d;
  
  /* initialize EAL */
  
  printf("** Initalizing EAL.\n");
  ret = rte_eal_init(argc, argv);
  if (ret < 0)
    rte_panic("EAL init failed.\n");
  
  master_core_id = rte_get_master_lcore();
  printf("Master Core ID = %d\n", master_core_id);
  
  RTE_LCORE_FOREACH_SLAVE(lcore_id) {
    rte_eal_remote_launch(lcore_ready, NULL, lcore_id);
  }
  
  lcore_ready(NULL); //call on master core
  rte_eal_mp_wait_lcore();
  
  /* configure Ethernet device */
  nb_ports = rte_eth_dev_count();
  printf("Number of ports active: %u\n", nb_ports);
  
  /* initalize memory packet buffers */
  printf("Initializing memory buffers.\n");
  mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
				      MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  
  if (mbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
  
  
  /* Initialize all ports. */
  printf("** Initializing ports.\n");
  for (portid = 0; portid < nb_ports; portid++)
    if (port_init(portid, mbuf_pool) != 0)
      rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",
	       portid);	
  
  
  
  /* setup memory for tx_mbufs */
  
  struct mbuf_table *mtb;
  uint32_t n;
  size_t sz;
  
  n = RTE_MAX(max_flow_num, 2UL * MAX_PKT_BURST);
  sz = sizeof (*mtb) + sizeof (mtb->m_table[0]) *  n;
  
  if ((mtb = rte_zmalloc_socket(__func__, sz, RTE_CACHE_LINE_SIZE,
				rte_socket_id())) == NULL) {
    fprintf(stderr, "error allocating memory for tx_mbufs\n");
    return -1;
  }
  
  mtb->len = n;
  tx_mbufs = mtb;
  
  lcore_main();
  
  return 0;
}
