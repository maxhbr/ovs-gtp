#ifndef __NET_GTP_WRAPPER_H
#define __NET_GTP_WRAPPER_H  1

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
#ifdef CONFIG_INET
#include <net/udp_tunnel.h>
#endif /* ifdef CONFIG_INET */

#include_next <net/gtp.h>

#define gtp_xmit dev_queue_xmit

struct net_device *rpl_gtp_dev_create_fb(
	struct net *net, const char *name, u8 name_assign_type, u16 dst_port);
#define gtp_create_flow_based_dev rpl_gtp_create_flow_based_dev


#define gtp_init_module rpl_gtp_init_module
#define gtp_cleanup_module rpl_gtp_cleanup_module
int rpl_gtp_init_module(void);
void rpl_gtp_cleanup_module(void);

#endif /* 4.7 kernel */
#endif /* __NET_GTP_WRAPPER_H */
