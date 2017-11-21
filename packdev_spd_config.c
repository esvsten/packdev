/*                        *
 * SPD configuration file *
 *                        */

#include <sys/types.h>

#include <rte_ether.h>
#include <rte_ip.h>

#include "packdev_common.h"
#include "packdev_acl_config.h"

static struct rte_acl_ctx *global_context;

/* TODO: SPD to SAD mapping, it is required for          *
 * - Decryption: Verify packet arrived on the correct SA *
 * - Encryption: Find the correct SA to encrypt on       */
void packdev_spd_config_init() {
    /* Add static ACL rules here */
    struct acl_ipv4_rule acl_rules[4];
    acl_rules[0] = packdev_acl_add_ipv4_rule(
            PACKDEV_ACL_ACCEPT, 1 /* priority */,
            0, 0, // protocol
            0, 0, // source address
            IPv4(192,168,0,0), IPv4(192,168,0,255), // destination address
            0, 0xffff, // source port
            0, 0xffff); // destination port

    acl_rules[1] = packdev_acl_add_ipv4_rule(
            PACKDEV_ACL_ACCEPT, 2 /* priority */,
            0, 0, // protocol
            0, 0, // source address
            IPv4(192,168,1,0), IPv4(192,168,1,255), // destination address
            0, 0xffff, // source port
            0, 0xffff); // destination port

    acl_rules[2] = packdev_acl_add_ipv4_rule(
            PACKDEV_ACL_ACCEPT, 3 /* priority */,
            17, 0xff, // protocol
            IPv4(192,168,17,114), IPv4(192,168,17,114), // source address
            IPv4(192,168,16,36), IPv4(192,168,16,36), // source address
            0, 0xffff, // source port
            0, 0xffff); // destination port

    acl_rules[3] = packdev_acl_add_ipv4_rule(
            PACKDEV_ACL_DENY, 4 /* priority */,
            17, 0xff, // protocol
            IPv4(192,168,17,114), IPv4(192,168,17,114), // source address
            IPv4(192,168,16,36), IPv4(192,168,16,36), // source address
            46531, 46531, // source port
            0, 0xffff); // destination port

    global_context = packdev_acl_setup_context(
            "packdev-spd-ipv4",
            RTE_DIM(acl_rules),
            (const struct rte_acl_rule*)acl_rules);
}

struct rte_acl_ctx* packdev_spd_config_get_context() {
    return global_context;
}
