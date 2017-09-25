
#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include <rte_ether.h>

#include "ip_fastpath.h"
/* 

 * Init EAL
 * Init lcores ??
 * Init mbufs
 * Init Rx and Tx queues

 */

#define PROMISCIOUS_MODE 0

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191 // number of memory buffers allocated
#define MBUF_CACHE_SIZE 250 // size of each memory buffer in bytes
#define BURST_SIZE 32

#define LOCAL_DMAC_ADR 0x080027f152c2
#define DMAC_MASK_BYTE_0 0xFF0000000000
#define DMAC_MASK_BYTE_1 0x00FF00000000
#define DMAC_MASK_BYTE_2 0x0000FF000000
#define DMAC_MASK_BYTE_3 0x000000FF0000
#define DMAC_MASK_BYTE_4 0x00000000FF00
#define DMAC_MASK_BYTE_5 0x0000000000FF

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
	    

static int lcore_hello(__attribute__((unused)) void *arg)
{
	unsigned lcore_id;
	lcore_id = rte_lcore_id();
	if (lcore_id == rte_get_master_lcore())
	  printf("hello from master core %u\n", lcore_id);
	else
	  printf("hello from slave core %u\n", lcore_id);
	return 0;
}


static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;


	if (port >= rte_eth_dev_count())
		return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);


	
	return 0;
}
#if 0
/* dump content of mbuf to screen */
void dump_mbuf(mbuf *m){

  


}
#endif


void print_dmac_adr(struct ether_hdr *eth_hdr){


    printf("%x %x %x %x %x %x\n", eth_hdr->d_addr.addr_bytes[0], eth_hdr->d_addr.addr_bytes[1], eth_hdr->d_addr.addr_bytes[2],eth_hdr->d_addr.addr_bytes[3], eth_hdr->d_addr.addr_bytes[4],eth_hdr->d_addr.addr_bytes[5]);

    

}
void print_smac_adr(struct ether_hdr *eth_hdr){


    printf("%x %x %x %x %x %x\n", eth_hdr->s_addr.addr_bytes[0], eth_hdr->s_addr.addr_bytes[1], eth_hdr->s_addr.addr_bytes[2],eth_hdr->s_addr.addr_bytes[3], eth_hdr->s_addr.addr_bytes[4],eth_hdr->s_addr.addr_bytes[5]);


}

int match_dmac_adr(struct ether_hdr *eth_hdr){

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



/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

static __attribute__((noreturn)) void
lcore_main(void)
{
	const uint8_t nb_ports = rte_eth_dev_count();
	uint8_t port;
	int packets_rec=0;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ipv4_hdr;
	struct udp_hdr *udp_hdr;
	
	ipv4_ing_session_table *ing_session[MAX_ING_SESSIONS];
	
	
	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	for (port = 0; port < nb_ports; port++)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	/* Run until the application is quit or killed. */
	for (;;) {
		/*
		 * Receive packets on a port and forward them on the paired
		 * port. The mapping is 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, etc.
		 */
		for (port = 0; port < nb_ports; port++) {

			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0, //nb_rx = number of packets in rx burst
					bufs, BURST_SIZE);
			if (nb_rx != 0){
			  printf("---\n");
			  printf("nb_rx = %d\n", nb_rx);
			  eth_hdr = rte_pktmbuf_mtod(bufs[nb_rx-1], struct ether_hdr *);

			  printf("packet received from MAC address ");
			  print_smac_adr(eth_hdr);
			  printf("destination MAC address ");
			  print_dmac_adr(eth_hdr);
			  if (match_dmac_adr(eth_hdr)!=1){ //discard if no dmac match
			    rte_pktmbuf_free(bufs[nb_rx]);
			    break;
			  }
			  
			  			  
			  if (rte_bswap16(eth_hdr->ether_type) == ETHER_TYPE_IPv4){
			    ipv4_hdr = eth_hdr+1; // point to beginning of IPv4 header
			         

			    printf("Ethernet II frame containing IPv4\n");
			    printf("IPv4 dest address 0x%08x\n", rte_bswap32(ipv4_hdr->dst_addr));
			    printf("IPv4 source address 0x%08x\n", rte_bswap32(ipv4_hdr->src_addr));
			    if (ipv4_hdr->next_proto_id == PROTO_UDP){
			      printf("Encapsulated protocol is UDP\n");
			      udp_hdr = ipv4_hdr+1; // point to beginning of UDP header
			      printf("UDP dest port %d\n",rte_bswap16(udp_hdr->dst_port));
			      printf("UDP source port %d\n", rte_bswap16(udp_hdr->src_port));
			    }
			    
			  }
			  else
			    printf("Packet type is not IPv4\n");

			}
			if (unlikely(nb_rx == 0))
				continue;

			
#if 0
			/* Send burst of TX packets, to second port of pair. */
			const uint16_t nb_tx = rte_eth_tx_burst(port ^ 1, 0,
					bufs, nb_rx);

			/* Free any unsent packets. */
			if (unlikely(nb_tx < nb_rx)) {
				uint16_t buf;
				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(bufs[buf]);

			}
		     #endif
		}
	}
}




int main(int argc, char **argv)
{
	int ret;
	unsigned lcore_id;
	unsigned master_core_id;
	struct rte_eth_conf port_conf = port_conf_default; // structure containing ethernet port configuration & options
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
	
	/* call helloworld() on every slave lcore */
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
	  printf("calling hello() on slave core\n");
	  rte_eal_remote_launch(lcore_hello, NULL, lcore_id);
	}

	lcore_hello(NULL); //call on master core
	rte_eal_mp_wait_lcore();
	
	/* configure Ethernet device */
	nb_ports = rte_eth_dev_count();
	printf("Number of ports active: %u\n", nb_ports);

	/* initalize memory packet buffers */
	printf("** Initializing memory buffers.\n");
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
	



	/* allocte mbuf from master core */
#if 0		   
	mbuf = rte_pktmbuf_alloc(mbuf_pool);
	//	memcpy(mbuf->
	printf("mbuf length = %u\n", mbuf->buf_len);
	printf("mbuf timestamp = %u\n", mbuf->timestamp);

	iph = (struct ipv4_hdr *)rte_pktmbuf_append(mbuf, sizeof(struct ipv4_hdr)); // append data to packet buffer and return start of data (ipv4 header)

	
	
	iph->version_ihl = 0b01000101;
	iph->type_of_service = 0;
	iph->total_length = 64;
	iph->packet_id = 0xffff;
	iph->fragment_offset = 0;
	iph->time_to_live = 0xaa;
	iph->next_proto_id = 0xbb;
	iph->hdr_checksum = 0xabcd;
	iph->src_addr = 0xdeadbeef;
	iph->dst_addr = 0xabadcafe;
	
	printf("length of mbuf data segment = %d\n", mbuf->data_len);
#endif
	lcore_main();
	
	return 0;
}
