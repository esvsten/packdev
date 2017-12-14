
/* Fast Path packet processing prototype

   see also: ip_fastpath.h

   sven.s.stenstrom@ericsson.com

 */

#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <strings.h>
#include <assert.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_acl.h>

#include "packdev_common.h"
#include "packdev_acl_config.h"
#include "packdev_acl.h"

void packdev_acl_classify_bulk(
        uint32_t num_pkts,
        struct rte_mbuf *pkts[],
        uint32_t result[]) {
    struct rte_acl_ctx *context = packdev_acl_config_get_context();
    assert(context != NULL);

    const uint8_t *data[DEFAULT_PKT_BURST];
    for (uint32_t i = 0; i < num_pkts; ++i) {
        data[i] = (const uint8_t*)MBUF_IPV4_HDR_PTR(pkts[i]);
    }

    rte_acl_classify(
            context,
            data,
            result,
            num_pkts,
            MAX_ACL_CATEGORIES);
}

uint32_t packdev_acl_classify(struct rte_mbuf *pkt) {
    struct rte_acl_ctx *context = packdev_acl_config_get_context();
    assert(context != NULL);

    uint32_t num_pkts = 1;
    uint32_t result = 0;
    const uint8_t *ipv4_offset = (const uint8_t*)MBUF_IPV4_HDR_PTR(pkt);
    rte_acl_classify(
            context,
            &ipv4_offset,
            &result,
            num_pkts,
            MAX_ACL_CATEGORIES);

    return result;
}
