/*                        *
 * SPD configuration file *
 *                        */

#include <glib.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include <rte_ether.h>
#include <rte_ip.h>

#include "packdev_common.h"
#include "packdev_acl_config.h"

#define SPD_CONFIG_FILE "packdev_spd.conf"

static struct rte_acl_ctx *global_context;

/* TODO: SPD to SAD mapping, it is required for          *
 * - Decryption: Verify packet arrived on the correct SA *
 * - Encryption: Find the correct SA to encrypt on       */
void packdev_spd_config_init() {

    GError *error = NULL;
    GKeyFile *gkf = g_key_file_new();
    if (!g_key_file_load_from_file(gkf, SPD_CONFIG_FILE, G_KEY_FILE_NONE, NULL)) {
        rte_panic("Could not read config file %s\n", SPD_CONFIG_FILE);
    }

    gsize num_policies = 0;
    gchar **policies = g_key_file_get_groups(gkf, &num_policies);
    struct acl_ipv4_rule *spd_rules = malloc(num_policies * sizeof(struct acl_ipv4_rule));
    for (guint index = 0; index < num_policies; index++) {
         gchar *action = g_key_file_get_string(gkf, policies[index], "action", &error);
         packdev_acl_result_t acl_action = PACKDEV_ACL_NO_MATCH;
         if (strcmp(action, "ACCEPT") == 0) {
             acl_action = PACKDEV_ACL_ACCEPT;
         } else if (strcmp(action, "DENY") == 0) {
             acl_action = PACKDEV_ACL_DENY;
         }
         gint priority = g_key_file_get_integer(gkf, policies[index], "priority", &error);
         gint protocol = g_key_file_get_integer(gkf, policies[index], "protocol", &error);
         gint protocol_mask = g_key_file_get_integer(gkf, policies[index], "protocol_mask", &error);
         gint src_ip_addr_begin;
         inet_pton(AF_INET, g_key_file_get_string(gkf, policies[index], "src_ip_addr_begin", &error),
                     &src_ip_addr_begin);
         gint src_ip_addr_end;
         inet_pton(AF_INET, g_key_file_get_string(gkf, policies[index], "src_ip_addr_end", &error),
                     &src_ip_addr_end);
         gint dst_ip_addr_begin;
         inet_pton(AF_INET, g_key_file_get_string(gkf, policies[index], "dst_ip_addr_begin", &error),
                     &dst_ip_addr_begin);
         gint dst_ip_addr_end;
         inet_pton(AF_INET, g_key_file_get_string(gkf, policies[index], "dst_ip_addr_end", &error),
                     &dst_ip_addr_end);
         gint src_port_begin = g_key_file_get_integer(gkf, policies[index], "src_port_begin", &error);
         gint src_port_end = g_key_file_get_integer(gkf, policies[index], "src_port_end", &error);
         gint dst_port_begin = g_key_file_get_integer(gkf, policies[index], "dst_port_begin", &error);
         gint dst_port_end = g_key_file_get_integer(gkf, policies[index], "dst_port_end", &error);
         spd_rules[index] = packdev_acl_add_ipv4_rule(
                 acl_action, priority,
                 protocol, protocol_mask,
                 rte_bswap32(src_ip_addr_begin),
                 rte_bswap32(src_ip_addr_end),
                 rte_bswap32(dst_ip_addr_begin),
                 rte_bswap32(dst_ip_addr_end),
                 src_port_begin, src_port_end,
                 dst_port_begin, dst_port_end);
    }

    g_key_file_free (gkf);

    global_context = packdev_acl_setup_context(
            "packdev-spd-ipv4",
            num_policies,
            (const struct rte_acl_rule*)spd_rules);
    free(spd_rules);
}

struct rte_acl_ctx* packdev_spd_config_get_context() {
    return global_context;
}
