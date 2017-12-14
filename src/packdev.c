
/* Fast Path packet processing prototype

   see also: ip_fastpath.h

   sven.s.stenstrom@ericsson.com

 */

#include <sys/types.h>
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <strings.h>
#include <assert.h>

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

#include <packdev_common.h>
#include "packdev_config.h"
#include <packdev_packet.h>
#include <packdev_crypto.h>
#include <packdev_port.h>
#include <packdev_eth.h>
#include <packdev_nbr.h>
#include <packdev_ipv4.h>
#include <packdev_l2_config.h>
#include <packdev_l3_config.h>
#include <packdev_ipv4_flow.h>
#include <packdev_acl_config.h>
#include <packdev_spd_config.h>
#include <packdev_sa_config.h>
#include <packdev_session.h>

static __attribute__((noreturn)) void packdev_lcore_main_loop(uint8_t lcore_id) {
    (void)lcore_id;
    const uint8_t num_ports = rte_eth_dev_count();
    const uint16_t num_pkts = DEFAULT_PKT_BURST;
    struct rte_mbuf *pkt_mbufs[DEFAULT_PKT_BURST];

    // ensure there are even number of ports
    assert(num_ports%2 == 0);

    rte_log_set_global_level(RTE_LOG_DEBUG);
    // init devices
    packdev_port_init();
    packdev_crypto_init();

    // init data plane modules
    packdev_nbr_init();
    packdev_ipv4_init();

    // init control plane modules
    packdev_config_init();
    packdev_l2_config_init();
    packdev_l3_config_init();
    packdev_ipv4_flow_init(); /* ACL, SPD and sessions */
    packdev_sa_config_init();

    for (uint8_t port_id = 0; port_id < num_ports; port_id++) {
        if (rte_eth_dev_socket_id(port_id) > 0 &&
                rte_eth_dev_socket_id(port_id) != (int)rte_socket_id()) {
            RTE_LOG(INFO, USER1,
                    "NUMA node(%u) is remote relative to polling thread\n",
                    port_id);
        }
    }

    // associate veth ports with eth ports
    uint8_t num_of_eth_ports = num_ports/2;
    for (uint8_t port_id = 0; port_id < num_of_eth_ports; port_id++) {
        packdev_config_port_map(port_id, port_id + num_of_eth_ports);
    }

    while(1) {
        for (uint8_t port_id = 0; port_id < num_ports; port_id++) {
            uint16_t queue_id = 0;
            packdev_packet_receive(port_id, queue_id, pkt_mbufs, num_pkts);
        }

        for (uint8_t port_id = 0; port_id < num_ports; port_id++) {
            packdev_packet_flush_all(port_id);
        }
    }
}

static int launch_one_core(__attribute__((unused)) void *arg) {
    uint32_t lcore_id = rte_lcore_id();
    if (lcore_id == rte_get_master_lcore()) {
        RTE_LOG(INFO, USER1, "master core %u ready\n", lcore_id);
        RTE_LOG(INFO, USER1, "Starting main loop on lcore(%u)\n", lcore_id);
        packdev_lcore_main_loop(lcore_id);
    } else {
        RTE_LOG(INFO, USER1, "slave core %u ready\n", lcore_id);
    }

    return 0;
}

#define MAX_BACKTRACE   32
static void signal_handler(int sig __rte_unused)
{
    if (sig == SIGINT) {
        signal(sig, SIG_IGN);
        printf("Ojj, did you hit Ctrl-C?\n");
        printf("Do you really want to quit PACKDEV? [y/n] ");
        fflush(stdout);
        char c = getchar();
        if (c == 'y' || c == 'Y') {
            packdev_port_destroy();
            exit(0);
        }

        signal(sig, signal_handler);
        return;
    }

    RTE_LOG(CRIT, USER1, "\n======");
    if (sig == SIGSEGV) {
        RTE_LOG(CRIT, USER1, "PACKDEV: Got a Segment Fault\n");
    } else if (sig == SIGHUP) {
        RTE_LOG(CRIT, USER1, "PACKDEV: Got a SIGHUP\n");
    } else {
        RTE_LOG(CRIT, USER1, "PACKDEV: Got a signal %d\n", sig);
    }
    RTE_LOG(CRIT, USER1, "\n");

    void *array[MAX_BACKTRACE];
    size_t size = backtrace(array, MAX_BACKTRACE);
    char **strings = backtrace_symbols (array, size);
    RTE_LOG(CRIT, USER1, "Obtained %zd stack frames.\n", size);
    for (size_t i = 0; i < size; i++) {
        RTE_LOG(CRIT, USER1, "%s\n", strings[i]);
    }

    free (strings);
    abort();
}

int main(int argc, char **argv) {
    unsigned lcore_id;
    unsigned master_core_id;

    signal(SIGSEGV, signal_handler);
    signal(SIGHUP, signal_handler);
    signal(SIGINT, signal_handler);

    RTE_LOG(INFO, EAL, "** Initalizing EAL.\n");
    if (rte_eal_init(argc, argv) < 0) {
        rte_panic("EAL init failed.\n");
    }

    master_core_id = rte_get_master_lcore();
    RTE_LOG(INFO, USER1, "Master Core ID = %d\n", master_core_id);

    if (rte_lcore_count() > 1) {
        rte_panic("\nWARNING: Too many lcores enabled. Only 1 used.\n");
    }

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        rte_eal_remote_launch(launch_one_core, NULL, lcore_id);
    }

    launch_one_core(NULL); //call on master core
    rte_eal_mp_wait_lcore();

    packdev_port_destroy();

    return 0;
}
