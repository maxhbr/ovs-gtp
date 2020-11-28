/*
 * Copyright 2020 The Magma Authors.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/net.h>
#include <linux/rculist.h>
#include <linux/udp.h>
#include <linux/if_vlan.h>
#include <linux/module.h>

#include <net/gtp.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/udp.h>
#include <net/xfrm.h>

#include "datapath.h"
#include "vport.h"
#include "vport-netdev.h"

extern struct net_device *gtp_create_flow_based_dev(struct net *net, const char *name,
						u8 name_assign_type, u16 dst_port);

static struct vport_ops ovs_gtp_vport_ops;
/**
 * struct gtp_port - Keeps track of open UDP ports
 * @dst_port: destination port.
 */
struct gtp_port {
    u16 port_no;
};

static inline struct gtp_port *gtp_vport(const struct vport *vport)
{
    return vport_priv(vport);
}

static int gtp_get_options(const struct vport *vport,
                           struct sk_buff *skb)
{
    struct gtp_port *gtp_port = gtp_vport(vport);

    if (nla_put_u16(skb, OVS_TUNNEL_ATTR_DST_PORT, gtp_port->port_no))
        return -EMSGSIZE;
    return 0;
}

static struct vport *gtp_tnl_create(const struct vport_parms *parms)
{
    struct net *net = ovs_dp_get_net(parms->dp);
    struct nlattr *options = parms->options;
    struct gtp_port *gtp_port;
    struct net_device *dev;
    struct vport *vport;
    struct nlattr *a;
    u16 dst_port;
    int err;

    if (!options) {
        err = -EINVAL;
        goto error;
    }

    a = nla_find_nested(options, OVS_TUNNEL_ATTR_DST_PORT);
    if (a && nla_len(a) == sizeof(u16)) {
        dst_port = nla_get_u16(a);
    } else {
        /* Require destination port from userspace. */
        err = -EINVAL;
        goto error;
    }

    vport = ovs_vport_alloc(sizeof(struct gtp_port),
                            &ovs_gtp_vport_ops, parms);
    if (IS_ERR(vport))
        return vport;

    gtp_port = gtp_vport(vport);
    gtp_port->port_no = dst_port;

    rtnl_lock();
    dev = gtp_create_flow_based_dev(net, parms->name, NET_NAME_USER, dst_port);
    if (IS_ERR(dev)) {
        rtnl_unlock();
        ovs_vport_free(vport);
        return ERR_CAST(dev);
    }

    err = dev_change_flags(dev, dev->flags | IFF_UP, NULL);
    if (err < 0) {
	rtnl_delete_link(dev);
	rtnl_unlock();
	ovs_vport_free(vport);
	goto error;
    }

    rtnl_unlock();
    return vport;
error:
    return ERR_PTR(err);
}

static struct vport *gtp_create(const struct vport_parms *parms)
{
    struct vport *vport;
    vport = gtp_tnl_create(parms);
    if (IS_ERR(vport))
        return vport;

    return ovs_netdev_link(vport, parms->name);
}


static struct vport_ops ovs_gtp_vport_ops = {
    .type                = OVS_VPORT_TYPE_GTPU,
    .create              = gtp_create,
    .get_options         = gtp_get_options,
    .destroy		 = ovs_netdev_tunnel_destroy,
    .send                = gtp_xmit,
};

static int __init ovs_gtp_tnl_init(void)
{
    return ovs_vport_ops_register(&ovs_gtp_vport_ops);
}

static void __exit ovs_gtp_tnl_exit(void)
{
    ovs_vport_ops_unregister(&ovs_gtp_vport_ops);
}

module_init(ovs_gtp_tnl_init);
module_exit(ovs_gtp_tnl_exit);

MODULE_DESCRIPTION("OVS: GTP switching port");
MODULE_LICENSE("GPL");
MODULE_ALIAS("vport-type-110");
