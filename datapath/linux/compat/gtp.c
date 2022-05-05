// SPDX-License-Identifier: GPL-2.0-or-later
/* GTP according to GSM TS 09.60 / 3GPP TS 29.060
 *
 * (C) 2012-2014 by sysmocom - s.f.m.c. GmbH
 * (C) 2016 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * Author: Harald Welte <hwelte@sysmocom.de>
 *	   Pablo Neira Ayuso <pablo@netfilter.org>
 *	   Andreas Schultz <aschultz@travelping.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/rculist.h>
#include <linux/jhash.h>
#include <linux/if_tunnel.h>
#include <linux/net.h>
#include <linux/file.h>
#include <linux/gtp.h>
#include <linux/sctp.h>

#include <net/dst_metadata.h>
#include <net/net_namespace.h>
#include <net/protocol.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/ipv6_stubs.h>
#include <net/icmp.h>
#include <net/xfrm.h>
#include <net/genetlink.h>
#include <net/netns/generic.h>
#include <net/gtp.h>

#include "gso.h"
#include "vport-netdev.h"
#include "compat.h"


#define GTP_PDP_HASHSIZE 1024
#define GTPA_PEER_ADDRESS GTPA_SGSN_ADDRESS /* maintain legacy attr name */
#define GTP_EXTENSION_HDR_FLAG 0x04
#define GTP_SEQ_FLAG           0x02

struct gtpu_ext_hdr {
	__be16 seq_num;
	u8 n_pdu;
		u8 type;
};

struct gtpu_ext_hdr_pdu_sc {
	u8 len;
	u8 pdu_type;
	u8 qfi;
		u8 next_type;
};

/* One instance of the GTP device. */
struct gtp_dev {
	struct list_head	list;

	struct net_device	*dev;
	struct sock		*sk1u;
	struct sock		*sk1u_v6;

	__be16			gtph_port;
};

static unsigned int gtp_net_id __read_mostly;

struct gtp_net {
	struct list_head gtp_dev_list;
};

static int check_header(struct sk_buff *skb, int len)
{
	if (unlikely(skb->len < len))
		return -EINVAL;
	if (unlikely(!pskb_may_pull(skb, len)))
		return -ENOMEM;
	return 0;
}

static int gtp_rx(struct sock *sk, struct gtp_dev *gtp, struct sk_buff *skb,
			unsigned int hdrlen, u8 gtp_version,
			__be64 tid, u8 flags, u8 type)
{
#ifndef USE_UPSTREAM_TUNNEL
	union {
		struct metadata_dst dst;
		char buf[sizeof(struct metadata_dst) + sizeof (struct gtpu_metadata)];
	} buf;
#endif
	struct pcpu_sw_netstats *stats;
	int err;

#ifndef USE_UPSTREAM_TUNNEL
		struct metadata_dst *tun_dst = &buf.dst;
#endif

		int opts_len;
	 	opts_len = sizeof (struct gtpu_metadata);
#ifndef USE_UPSTREAM_TUNNEL
		//udp_tun_rx_dst
		ovs_udp_tun_rx_dst(tun_dst, skb, sk->sk_family, TUNNEL_KEY, tid, opts_len);
#else
		struct metadata_dst *tun_dst =
			udp_tun_rx_dst(skb, sk->sk_family, TUNNEL_KEY, tid, opts_len);
#endif
		netdev_dbg(gtp->dev, "attaching metadata_dst to skb, gtp ver %d hdrlen %d\n", gtp_version, hdrlen);
                if (unlikely(opts_len)) {
                    struct gtpu_metadata *opts = ip_tunnel_info_opts(&tun_dst->u.tun_info);
                    struct gtp1_header *gtp1 = (struct gtp1_header *)(skb->data + sizeof(struct udphdr));
		    if (likely(type == GTP_TPDU)){
	                struct gtpu_ext_hdr *geh;
			geh = (struct gtpu_ext_hdr *) (gtp1 + 1);
			if (geh->type == 0x85) {
			    struct gtpu_ext_hdr_pdu_sc *pdu_sc_hd;
			    pdu_sc_hd = (struct gtpu_ext_hdr_pdu_sc *) (geh + 1);
			    if (pdu_sc_hd->qfi) {
                                opts_len = sizeof (struct gtpu_metadata);
                                opts->ver = GTP_METADATA_V1;
                                opts->flags = gtp1->flags;
                                opts->type = gtp1->type;
                                opts->qfi = pdu_sc_hd->qfi;
                                opts_len = opts_len + sizeof(struct gtpu_ext_hdr) + sizeof(struct gtpu_ext_hdr_pdu_sc);
                                tun_dst->u.tun_info.key.tun_flags |= TUNNEL_GTPU_OPT;
                                tun_dst->u.tun_info.options_len = opts_len;
                            }
                        }
		    } else {
		        opts->ver = GTP_METADATA_V1;
                        opts->flags = gtp1->flags;
                        opts->type = gtp1->type;
                        netdev_dbg(gtp->dev, "recved control pkt: flag %x type: %d\n", opts->flags, opts->type);
                        tun_dst->u.tun_info.key.tun_flags |= TUNNEL_GTPU_OPT;
                        tun_dst->u.tun_info.options_len = opts_len;
                        skb->protocol = 0xffff;         // Unknown
                    }
		}

		/* Get rid of the GTP + UDP headers. */
		if (iptunnel_pull_header(skb, hdrlen, skb->protocol,
					!net_eq(sock_net(sk), dev_net(gtp->dev)))) {
			err = -1;
			gtp->dev->stats.rx_length_errors++;
			goto err;
		}

		ovs_skb_dst_set(skb, &tun_dst->dst);
		netdev_dbg(gtp->dev, "forwarding packet from GGSN to uplink\n");

	/* Now that the UDP and the GTP header have been removed, set up the
	 * new network header. This is required by the upper layer to
	 * calculate the transport header.
	 */
	skb_reset_network_header(skb);
	if (!check_header(skb, sizeof(struct iphdr))) {
		struct iphdr *iph;

		iph = ip_hdr(skb);
		if (iph->version == 4) {
			netdev_dbg(gtp->dev, "inner pkt: ipv4");
			skb->protocol = htons(ETH_P_IP);
		} else if (iph->version == 6) {
			netdev_dbg(gtp->dev, "inner pkt: ipv6");
			skb->protocol = htons(ETH_P_IPV6);
		} else {
			netdev_dbg(gtp->dev, "inner pkt: control pkt");
		}
	}

	skb->dev = gtp->dev;

	stats = this_cpu_ptr(gtp->dev->tstats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += skb->len;
	u64_stats_update_end(&stats->syncp);

#ifndef USE_UPSTREAM_TUNNEL
	netdev_port_receive(skb, skb_tunnel_info(skb));
#else
	netif_rx(skb);
#endif
	return 0;

err:
	gtp->dev->stats.rx_dropped++;
	return err;
}

/* 1 means pass up to the stack, -1 means drop and 0 means decapsulated. */

static int gtp1u_udp_encap_recv(struct sock *sk, struct gtp_dev *gtp, struct sk_buff *skb)
{
	unsigned int hdrlen = sizeof(struct udphdr) +
				  sizeof(struct gtp1_header);
	struct gtp1_header *gtp1;

	if (!pskb_may_pull(skb, hdrlen))
		return -1;

	gtp1 = (struct gtp1_header *)(skb->data + sizeof(struct udphdr));

	netdev_dbg(gtp->dev, "flags %x type: %x\n", gtp1->flags, gtp1->type);
	if ((gtp1->flags >> 5) != GTP_V1)
		return 1;

	/* From 29.060: "This field shall be present if and only if any one or
	 * more of the S, PN and E flags are set.".
	 *
	 * If any of the bit is set, then the remaining ones also have to be
	 * set.
	 */
		if (gtp1->type == GTP_TPDU) {
			if (gtp1->flags & GTP_EXTENSION_HDR_FLAG) {
				struct gtpu_ext_hdr *geh;
				u8 next_hdr;

				geh = (struct gtpu_ext_hdr *) (gtp1 + 1);
				netdev_dbg(gtp->dev, "ext type type %d, seq:%d, n_pdu:%d\n", geh->type, geh->seq_num, geh->n_pdu);

				hdrlen += sizeof (struct gtpu_ext_hdr);
				next_hdr = geh->type;
				while (next_hdr) {
					u8 len = *(u8 *) (skb->data + hdrlen);

					hdrlen += (len * 4);
					if (!pskb_may_pull(skb, hdrlen)) {
						netdev_dbg(gtp->dev, "malformed packet %d", hdrlen);
						return -1;
					}
					next_hdr = *(u8*) (skb->data + hdrlen - 1);
					netdev_dbg(gtp->dev, "current hdr len %d next hdr type: %d\n", len, next_hdr);
				}
				netdev_dbg(gtp->dev, "pkt type: %x", *(u8*) (skb->data + hdrlen));
				netdev_dbg(gtp->dev, "skb-len %d gtp len %d hdr len %d\n", skb->len, (int) ntohs(gtp1->length), hdrlen);
			} else if (gtp1->flags & GTP1_F_MASK)
				hdrlen += 4;
		}

	/* Make sure the header is larger enough, including extensions. */
	if (!pskb_may_pull(skb, hdrlen))
		return -1;

	gtp1 = (struct gtp1_header *)(skb->data + sizeof(struct udphdr));

	return gtp_rx(sk, gtp, skb, hdrlen, GTP_V1, key32_to_tunnel_id(gtp1->tid), gtp1->flags, gtp1->type);
}

static void __gtp_encap_destroy(struct sock *sk)
{
	struct gtp_dev *gtp;

	lock_sock(sk);
	gtp = sk->sk_user_data;
	if (gtp) {
		gtp->sk1u = NULL;
		gtp->sk1u_v6 = NULL;
		udp_sk(sk)->encap_type = 0;
		rcu_assign_sk_user_data(sk, NULL);
		sock_put(sk);
	}
	release_sock(sk);
}

static void gtp_encap_destroy(struct sock *sk)
{
	__gtp_encap_destroy(sk);
}

static void gtp_encap_disable_sock(struct sock *sk)
{
	if (!sk)
		return;

	__gtp_encap_destroy(sk);
}

static void gtp_encap_disable(struct gtp_dev *gtp)
{
	gtp_encap_disable_sock(gtp->sk1u);
	gtp_encap_disable_sock(gtp->sk1u_v6);
}

/* UDP encapsulation receive handler. See net/ipv4/udp.c.
 * Return codes: 0: success, <0: error, >0: pass up to userspace UDP socket.
 */
static int gtp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct gtp_dev *gtp;
	int ret = 0;

	gtp = rcu_dereference_sk_user_data(sk);
	if (!gtp)
		return 1;

	netdev_dbg(gtp->dev, "encap_recv sk=%p type %d\n", sk, udp_sk(sk)->encap_type);

	ret = gtp1u_udp_encap_recv(sk, gtp, skb);
	switch (ret) {
	case 1:
		netdev_dbg(gtp->dev, "pass up to the process\n");
		break;
	case 0:
		break;
	case -1:
		netdev_dbg(gtp->dev, "GTP packet has been dropped\n");
		kfree_skb(skb);
		ret = 0;
		break;
	}

	return ret;
}

static int gtp_dev_init(struct net_device *dev)
{
	struct gtp_dev *gtp = netdev_priv(dev);

	gtp->dev = dev;

	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;

	return 0;
}

static void gtp_dev_uninit(struct net_device *dev)
{
	struct gtp_dev *gtp = netdev_priv(dev);

	gtp_encap_disable(gtp);
	free_percpu(dev->tstats);
}

static unsigned int skb_gso_transport_seglen(const struct sk_buff *skb)
{
		const struct skb_shared_info *shinfo = skb_shinfo(skb);
		unsigned int thlen = 0;

		if (skb->encapsulation) {
				thlen = skb_inner_transport_header(skb) -
						skb_transport_header(skb);

				if (likely(shinfo->gso_type & (SKB_GSO_TCPV4 | SKB_GSO_TCPV6)))
						thlen += inner_tcp_hdrlen(skb);
		} else if (likely(shinfo->gso_type & (SKB_GSO_TCPV4 | SKB_GSO_TCPV6))) {
				thlen = tcp_hdrlen(skb);
		} else if (unlikely(skb_is_gso_sctp(skb))) {
				thlen = sizeof(struct sctphdr);
		} else if (shinfo->gso_type & SKB_GSO_UDP_L4) {
				thlen = sizeof(struct udphdr);
		}
		/* UFO sets gso_size to the size of the fragmentation
		 * payload, i.e. the size of the L4 (UDP) header is already
		 * accounted for.
		 */
		return thlen + shinfo->gso_size;
}

static unsigned int skb_gso_network_seglen(const struct sk_buff *skb)
{
		unsigned int hdr_len = skb_transport_header(skb) -
							   skb_network_header(skb);

		return hdr_len + skb_gso_transport_seglen(skb);
}

static inline void gtp1_push_header(struct net_device *dev, struct sk_buff *skb, __be32 tid, __u8 qfi)
{
	struct gtpu_ext_hdr *next_hdr;
	struct gtpu_ext_hdr_pdu_sc *pdu_sc;
	struct gtp1_header *gtp1;
	int payload_len;
	__u8 flags = 0x30;

	if (skb_is_gso(skb)) {
		payload_len = skb_gso_network_seglen(skb);
		netdev_dbg(dev, "gso_size %d skb_gso_network_seglen(skb) %d skb->len %d\n",
				skb_shinfo(skb)->gso_size, skb_gso_network_seglen(skb), skb->len);
	} else {
		netdev_dbg(dev,"No gso len %d\n", skb->len);
		payload_len = skb->len;
	}
	if (qfi) {
		gtp1 = (struct gtp1_header *) skb_push(skb, sizeof(*gtp1) + sizeof (*next_hdr) + sizeof (*pdu_sc));
		payload_len += (sizeof(*next_hdr) + sizeof(*pdu_sc));
		flags = flags | GTP_EXTENSION_HDR_FLAG;
	} else {
		gtp1 = (struct gtp1_header *) skb_push(skb, sizeof(*gtp1));
	}

	/* Bits    8  7  6  5  4  3  2	1
	 *	  +--+--+--+--+--+--+--+--+
	 *	  |version |PT| 0| E| S|PN|
	 *	  +--+--+--+--+--+--+--+--+
	 *	    0  0  1  1	1  0  0  0
	 */
	gtp1->flags	= flags; /* v1, GTP-non-prime. */
	gtp1->type	= GTP_TPDU;
	gtp1->length	= htons(payload_len);
	gtp1->tid	= tid;

		if (qfi) {
				/* TODO: Suppport for extension header, sequence number and N-PDU.
				 *       Update the length field if any of them is available.
				 */
				struct gtpu_ext_hdr_pdu_sc pdu_sc_hdr;
				pdu_sc_hdr.len = 1;
                                pdu_sc_hdr.pdu_type = 0x0; /* PDU_TYPE_DL_PDU_SESSION_INFORMATION */
                                pdu_sc_hdr.qfi = qfi;
                                pdu_sc_hdr.next_type = 0;

			        next_hdr = (struct gtpu_ext_hdr *) (gtp1 + 1);
				next_hdr->type = 0x85;
				pdu_sc = (struct gtpu_ext_hdr_pdu_sc *) (next_hdr + 1);
				*pdu_sc = pdu_sc_hdr;
				netdev_dbg(dev,"Update QFI value for downlink %d for teid %d\n", pdu_sc->qfi, tid);
		}

}

static inline int gtp1_push_control_header(struct sk_buff *skb, __be32 tid, struct gtpu_metadata *opts,
		struct net_device *dev)
{
	struct gtp1_header *gtp1c;
	int payload_len;

	if (opts->ver != GTP_METADATA_V1) {
		return -ENOENT;
	}

	if (opts->type == 0xFE) {
		// for end marker ignore skb data.
		netdev_dbg(dev, "xmit pkt with null data");
		pskb_trim(skb, 0);
	}
	if (skb_cow_head(skb, sizeof (*gtp1c)) < 0)
		return -ENOMEM;

	payload_len = skb->len;

	gtp1c = (struct gtp1_header *) skb_push(skb, sizeof(*gtp1c));

	gtp1c->flags	= opts->flags;
	gtp1c->type	= opts->type;
	gtp1c->length	= htons(payload_len);
	gtp1c->tid	= tid;
	netdev_dbg(dev, "GTP control pkt: ver %d flags %x type %x pkt len %d tid %x",
			   opts->ver, opts->flags, opts->type, skb->len, tid);
	return 0;
}

static struct rtable *gtp_get_v4_rt(struct sk_buff *skb,
									   struct net_device *dev,
									   struct sock *gs4,
									   struct flowi4 *fl4,
									   const struct ip_tunnel_info *info)
{
	struct rtable *rt = NULL;

	if (!gs4)
		return ERR_PTR(-EIO);

	memset(fl4, 0, sizeof(*fl4));
	fl4->flowi4_mark = skb->mark;
	fl4->flowi4_proto = IPPROTO_UDP;
	fl4->daddr = info->key.u.ipv4.dst;
	fl4->saddr = info->key.u.ipv4.src;
	fl4->flowi4_tos = RT_TOS(info->key.tos);

	rt = ip_route_output_key(dev_net(dev), fl4);
	if (IS_ERR(rt)) {
		netdev_dbg(dev, "no route to %pI4\n", &fl4->daddr);
		return ERR_PTR(-ENETUNREACH);
	}
	if (rt->dst.dev == dev) { /* is this necessary? */
		netdev_dbg(dev, "circular route to %pI4\n", &fl4->daddr);
		ip_rt_put(rt);
		return ERR_PTR(-ELOOP);
	}
	return rt;
}

static struct dst_entry *gtp_get_v6_rt(struct sk_buff *skb,
									   struct net_device *dev,
									   struct sock *gs6,
									   struct flowi6 *fl6,
									   const struct ip_tunnel_info *info)
{
	struct dst_entry *ndst;

	if (!gs6)
		return ERR_PTR(-EIO);

	memset(fl6, 0, sizeof(*fl6));
	fl6->flowi6_mark = skb->mark;
	fl6->flowi6_proto = IPPROTO_UDP;
	fl6->daddr = info->key.u.ipv6.dst;
	fl6->saddr = info->key.u.ipv6.src;
	fl6->flowlabel = ip6_make_flowinfo(RT_TOS(info->key.tos), info->key.label);

	ndst = ipv6_stub->ipv6_dst_lookup_flow(dev_net(dev), gs6,
						   fl6, NULL);
	if (IS_ERR(ndst)) {
		netdev_dbg(dev, "no route to %pI6\n", &fl6->daddr);
		return ERR_PTR(-ENETUNREACH);
	}

	if (unlikely(ndst->dev == dev)) {
		netdev_dbg(dev, "circular route to %pI6\n", &fl6->daddr);
		dst_release(ndst);
		return ERR_PTR(-ELOOP);
	}

	return ndst;
}

static netdev_tx_t gtp_dev_xmit_fb(struct sk_buff *skb, struct net_device *dev)
{
	struct ip_tunnel_info *info = skb_tunnel_info(skb);
	struct gtp_dev *gtp = netdev_priv(dev);
	struct dst_entry *ndst = NULL;
	struct rtable *rt;
	struct flowi4 fl4;
	int min_headroom;
	struct flowi6 fl6;
	__be16 df;
		__u8 ttl;
		__u8 set_qfi = 0;
		__u8 csum;
		int err;
	int mtu;

	/* Read the IP destination address and resolve the PDP context.
	 * Prepend PDP header with TEI/TID from PDP ctx.
	 */

	if (!info) {
		netdev_dbg(dev, "no info for tunnel xmit\n");
		goto err;
	}

	if (ip_tunnel_info_af(info) == AF_INET) {
		rt = gtp_get_v4_rt(skb, dev, gtp->sk1u, &fl4, info);

		if (IS_ERR(rt)) {
				netdev_dbg(dev, "no route to SSGN %pI4\n", &fl4.daddr);
				dev->stats.tx_carrier_errors++;
				goto err;
		}
		skb_dst_drop(skb);
		csum = !!(info->key.tun_flags & TUNNEL_CSUM);
		err = udp_tunnel_handle_offloads(skb, csum);
		if (err)
			goto err_rt;
		ovs_skb_set_inner_protocol(skb, cpu_to_be16(ETH_P_IP));

		ttl = info->key.ttl;
		df = info->key.tun_flags & TUNNEL_DONT_FRAGMENT ? htons(IP_DF) : 0;

		/* hack to handle MTU */
		if (df) {
			mtu = dst_mtu(&rt->dst) - dev->hard_header_len -
				sizeof(struct iphdr) - sizeof(struct udphdr);
			mtu -= sizeof(struct gtp1_header);
		} else {
			mtu = dst_mtu(&rt->dst);
		}
		min_headroom = LL_RESERVED_SPACE(rt->dst.dev) + rt->dst.header_len
					+ sizeof(struct gtp1_header) + sizeof(struct iphdr)
					+ info->options_len;

		err = skb_cow_head(skb, min_headroom);
		if (unlikely(err))
			goto err_rt;

		netdev_dbg(dev, "packet with opt len %d", info->options_len);
		if (info->options_len == 0) {
		    gtp1_push_header(dev, skb, tunnel_id_to_key32(info->key.tun_id), set_qfi);
		} else if (info->key.tun_flags & TUNNEL_GTPU_OPT) {
		    struct gtpu_metadata *opts = ip_tunnel_info_opts(info);
		    __be32 tid = tunnel_id_to_key32(info->key.tun_id);
		    if (info->key.tun_flags & TUNNEL_OAM) {
                        set_qfi = opts->qfi;
			gtp1_push_header(dev, skb, tunnel_id_to_key32(info->key.tun_id), set_qfi);
                    }
                    else {
		        int err;
			err = gtp1_push_control_header(skb, tid, opts, dev);
			if (err) {
			    netdev_info(dev, "cntr pkt error %d", err);
			    goto err_rt;
			}
		    }
		} else {
		    netdev_dbg(dev, "Missing tunnel OPT");
		    goto err_rt;
		}
		udp_tunnel_xmit_skb(rt, gtp->sk1u, skb,
					fl4.saddr, fl4.daddr, fl4.flowi4_tos, ttl, df,
					gtp->gtph_port, gtp->gtph_port,
					!net_eq(sock_net(gtp->sk1u), dev_net(dev)),
								!csum);
	} else {
		ndst = gtp_get_v6_rt(skb, dev, gtp->sk1u_v6, &fl6, info);

		if (IS_ERR(ndst)) {
			netdev_dbg(dev, "no route to SSGN %pI4\n", &fl4.daddr);
			dev->stats.tx_carrier_errors++;
			goto err;
		}

		skb_dst_drop(skb);
		csum = !!(info->key.tun_flags & TUNNEL_CSUM);
		err = udp_tunnel_handle_offloads(skb, csum);
		if (err)
		    goto err_rt;
		netdev_dbg(dev, "skb->protocol %d\n", skb->protocol);
		ovs_skb_set_inner_protocol(skb, cpu_to_be16(ETH_P_IPV6));

		ttl = info->key.ttl;
		skb_scrub_packet(skb, !net_eq(sock_net(gtp->sk1u), dev_net(dev)));
	        if (info->options_len == 0) {
                    gtp1_push_header(dev, skb, tunnel_id_to_key32(info->key.tun_id), set_qfi);
                } else if (info->key.tun_flags & TUNNEL_GTPU_OPT) {
                    struct gtpu_metadata *opts = ip_tunnel_info_opts(info);
                    __be32 tid = tunnel_id_to_key32(info->key.tun_id);
                    if (info->key.tun_flags & TUNNEL_OAM) {
                        set_qfi = opts->qfi;
                        gtp1_push_header(dev, skb, tunnel_id_to_key32(info->key.tun_id), set_qfi);
                    } else {
                        int err;
                        err = gtp1_push_control_header(skb, tid, opts, dev);
                        if (err) {
                            netdev_info(dev, "cntr pkt error %d", err);
                            goto err_rt;
                        }
                    }
                } else {
                    netdev_dbg(dev, "Missing tunnel OPT");
                    goto err_rt;
                }

		udp_tunnel6_xmit_skb(ndst, gtp->sk1u_v6, skb, dev,
					&fl6.saddr, &fl6.daddr, RT_TOS(info->key.tos), ttl,
					info->key.label, gtp->gtph_port, gtp->gtph_port,
								!csum);
	}
	return NETDEV_TX_OK;
err_rt:
	ip_rt_put(rt);
err:
	dev->stats.tx_errors++;
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static netdev_tx_t gtp_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	/* Ensure there is sufficient headroom. */
	if (skb_cow_head(skb, dev->needed_headroom))
		goto tx_err;

	return gtp_dev_xmit_fb(skb, dev);
tx_err:
	dev->stats.tx_errors++;
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static int gtp_change_mtu(struct net_device *dev, int new_mtu, bool strict)
{
		int max_mtu = IP_MAX_MTU - dev->hard_header_len - sizeof(struct iphdr)
						- sizeof(struct udphdr) - sizeof(struct gtp1_header);

		if (new_mtu < ETH_MIN_MTU)
				return -EINVAL;

		if (new_mtu > max_mtu) {
				if (strict)
						return -EINVAL;

				new_mtu = max_mtu;
		}

		dev->mtu = new_mtu;
		return 0;
}

static struct socket *gtp_create_sock(struct net *net, bool ipv6)
{
	struct socket *sock;
	struct udp_port_cfg udp_conf;
	int err;

	memset(&udp_conf, 0, sizeof(udp_conf));

	if (ipv6) {
		udp_conf.family = AF_INET6;
		udp_conf.ipv6_v6only = 1;
	} else {
		udp_conf.family = AF_INET;
	}
	udp_conf.local_ip.s_addr = htonl(INADDR_ANY);
	udp_conf.local_udp_port = htons(GTP1U_PORT);

	err = udp_sock_create(net, &udp_conf, &sock);
	if (err < 0)
		return ERR_PTR(err);

	return sock;
}


static void gtp_setup_sock(struct gtp_dev *gtp,
									 struct net *net,
									 struct socket *sock)
{
	struct udp_tunnel_sock_cfg tunnel_cfg;

	memset(&tunnel_cfg, 0, sizeof(tunnel_cfg));
	tunnel_cfg.sk_user_data = gtp;
	tunnel_cfg.encap_rcv = gtp_encap_recv;
	tunnel_cfg.encap_destroy = gtp_encap_destroy;
	tunnel_cfg.encap_type = UDP_ENCAP_GTP1U;

	setup_udp_tunnel_sock(net, sock, &tunnel_cfg);

	sock_hold(sock->sk);
}


static int gtp_dev_open(struct net_device *dev)
{
	struct gtp_dev *gtp = netdev_priv(dev);
	struct net *net = dev_net(dev);
	struct socket *sock1u;
	struct socket *sock1u_v6;

	if (gtp->sk1u) {
		sock_hold(gtp->sk1u);
	} else {
		sock1u = gtp_create_sock(net, false);
		gtp_setup_sock(gtp, net, sock1u);
		gtp->sk1u = sock1u->sk;
	}

	if (gtp->sk1u_v6) {
		sock_hold(gtp->sk1u_v6);
	} else {
		sock1u_v6 = gtp_create_sock(net, true);
		gtp_setup_sock(gtp, net, sock1u_v6);
		gtp->sk1u_v6 = sock1u_v6->sk;
	}

	gtp->gtph_port = htons(GTP1U_PORT);

	return 0;
}

static int gtp_dev_stop(struct net_device *dev)
{
	struct gtp_dev *gtp = netdev_priv(dev);
	struct sock *sk;

	ASSERT_RTNL();
	if (gtp->sk1u) {
		sk = gtp->sk1u;

		sock_put(sk);
#ifdef HAVE_SOCK_REFCNT
		if (refcount_read(&sk->sk_refcnt) == 2) {
#else
		if (atomic_read(&sk->sk_refcnt) == 2) {
#endif
			udp_tunnel_sock_release(gtp->sk1u->sk_socket);
		}
	}

	if (gtp->sk1u_v6) {
		sk = gtp->sk1u_v6;

		sock_put(sk);
#ifdef HAVE_SOCK_REFCNT
		if (refcount_read(&sk->sk_refcnt) == 2) {
#else
		if (atomic_read(&sk->sk_refcnt) == 2) {
#endif
			udp_tunnel_sock_release(gtp->sk1u_v6->sk_socket);
		}
	}

	return 0;
}

static const struct net_device_ops gtp_netdev_ops = {
	.ndo_init		= gtp_dev_init,
	.ndo_uninit		= gtp_dev_uninit,
	.ndo_open               = gtp_dev_open,
	.ndo_stop               = gtp_dev_stop,
	.ndo_start_xmit		= gtp_dev_xmit,
	.ndo_get_stats64	= ip_tunnel_get_stats64,
};

static struct gtp_dev *gtp_find_flow_based_dev(
		struct net *net)
{
	struct gtp_net *gn = net_generic(net, gtp_net_id);
	struct gtp_dev *gtp, *t = NULL;

	list_for_each_entry(gtp, &gn->gtp_dev_list, list) {
		t = gtp;
	}

	return t;
}

static void gtp_link_setup(struct net_device *dev)
{
	dev->netdev_ops		= &gtp_netdev_ops;

#ifdef HAVE_NEEDS_FREE_NETDEV
	dev->needs_free_netdev	= true;
#endif
	dev->hard_header_len = 0;
	dev->addr_len = 0;

	/* Zero header length. */
	dev->type = ARPHRD_NONE;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;

	dev->priv_flags	 |= IFF_NO_QUEUE;

	dev->features    |= NETIF_F_LLTX;
	dev->features    |= NETIF_F_SG | NETIF_F_HW_CSUM;
	dev->features    |= NETIF_F_RXCSUM;
	dev->features    |= NETIF_F_GSO_SOFTWARE;

	dev->hw_features |= NETIF_F_SG | NETIF_F_HW_CSUM | NETIF_F_RXCSUM;
	dev->hw_features |= NETIF_F_GSO_SOFTWARE;


	netif_keep_dst(dev);

	dev->needed_headroom	= LL_MAX_HEADER +
				  sizeof(struct iphdr) +
				  sizeof(struct udphdr) +
				  sizeof(struct gtp1_header);

}

#ifdef HAVE_EXT_ACK_IN_RTNL_LINKOPS
static int gtp_newlink(struct net *src_net, struct net_device *dev,
			   struct nlattr *tb[], struct nlattr *data[],
			   struct netlink_ext_ack *extack)
#else
static int gtp_newlink(struct net *src_net, struct net_device *dev,
			   struct nlattr *tb[], struct nlattr *data[])
#endif
{
	struct gtp_dev *gtp;
	struct gtp_net *gn;
	int err;

	gtp = netdev_priv(dev);

	err = register_netdevice(dev);
	if (err < 0) {
		netdev_dbg(dev, "failed to register new netdev %d\n", err);
		goto out_encap;
	}

	gn = net_generic(dev_net(dev), gtp_net_id);
	list_add_rcu(&gtp->list, &gn->gtp_dev_list);
	netdev_dbg(dev, "registered new GTP interface\n");

	return 0;

out_encap:
	gtp_encap_disable(gtp);
	return err;
}

static void gtp_hashtable_free(struct net_device *dev)
{
	struct gtp_dev *gtp = netdev_priv(dev);

	list_del_rcu(&gtp->list);
}

static void gtp_dellink(struct net_device *dev, struct list_head *head)
{
	gtp_hashtable_free(dev);
	unregister_netdevice_queue(dev, head);
}

#ifdef HAVE_EXT_ACK_IN_RTNL_LINKOPS
static int gtp_validate(struct nlattr *tb[], struct nlattr *data[],
			struct netlink_ext_ack *extack)
#else
static int gtp_validate(struct nlattr *tb[], struct nlattr *data[])
#endif
{
	return 0;
}

static size_t gtp_get_size(const struct net_device *dev)
{
	return 0;
}

static int gtp_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	return 0;
}

static const struct nla_policy gtp_policy[IFLA_GTP_LWT_MAX + 1] = {
};

static struct rtnl_link_ops gtp_link_ops __read_mostly = {
	.kind		= "ovs_gtp",
	.maxtype	= IFLA_GTP_MAX,
	.policy		= gtp_policy,
	.priv_size	= sizeof(struct gtp_dev),
	.setup		= gtp_link_setup,
	.validate	= gtp_validate,
	.newlink	= gtp_newlink,
	.dellink	= gtp_dellink,
	.get_size	= gtp_get_size,
	.fill_info	= gtp_fill_info,
};

static int gtp_configure(struct net *net, struct net_device *dev)
{
	struct gtp_net *gn = net_generic(net, gtp_net_id);
	struct gtp_dev *gtp = netdev_priv(dev);
	int err;

	gtp->dev = dev;

	if (gtp_find_flow_based_dev(net))
		return -EBUSY;

	dev->netdev_ops         = &gtp_netdev_ops;

	dev->hard_header_len = 0;
	dev->addr_len = 0;

	/* Zero header length. */
	dev->type = ARPHRD_NONE;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;

	dev->priv_flags |= IFF_NO_QUEUE;
	dev->features   |= NETIF_F_LLTX;
	netif_keep_dst(dev);

	dev->needed_headroom    = LL_MAX_HEADER +
		sizeof(struct iphdr) +
		sizeof(struct udphdr) +
		sizeof(struct gtp0_header);

	err = register_netdevice(dev);
	if (err) {
		pr_err("Error when registering net device");
		return err;
	}

	list_add_rcu(&gtp->list, &gn->gtp_dev_list);
	return 0;
}

struct net_device *rpl_gtp_create_flow_based_dev(struct net *net,
		const char *name,
		u8 name_assign_type,
		u16 dst_port)
{
	struct nlattr *tb[IFLA_MAX + 1];
	struct net_device *dev;
	LIST_HEAD(list_kill);
	int err;

	memset(&tb, 0, sizeof(tb));
	dev = rtnl_create_link(net, name, name_assign_type,
			&gtp_link_ops, tb);
	if (IS_ERR(dev)) {
		pr_err("error rtnl_create_link");
		return dev;
	}

	err = gtp_configure(net, dev);
	if (err < 0) {
		pr_err("error gtp_configure");
		free_netdev(dev);
		return ERR_PTR(err);
	}

	/* openvswitch users expect packet sizes to be unrestricted,
	 * so set the largest MTU we can.
	 */
	err = gtp_change_mtu(dev, IP_MAX_MTU, false);
	if (err) {
		pr_err("error gtp_change_mtu");
		goto err;
	}

	err = rtnl_configure_link(dev, NULL);
	if (err < 0)  {
		pr_err("error rtnl_configure_link");
		goto err;
	}

	return dev;

err:
	gtp_dellink(dev, &list_kill);
	unregister_netdevice_many(&list_kill);
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(rpl_gtp_create_flow_based_dev);

static int __net_init gtp_net_init(struct net *net)
{
	struct gtp_net *gn = net_generic(net, gtp_net_id);

	INIT_LIST_HEAD(&gn->gtp_dev_list);
	return 0;
}

static void __net_exit gtp_net_exit(struct net *net)
{
	struct gtp_net *gn = net_generic(net, gtp_net_id);
	struct gtp_dev *gtp;
	LIST_HEAD(list);

	rtnl_lock();
	list_for_each_entry(gtp, &gn->gtp_dev_list, list)
		gtp_dellink(gtp->dev, &list);

	unregister_netdevice_many(&list);
	rtnl_unlock();
}

static struct pernet_operations gtp_net_ops = {
	.init	= gtp_net_init,
	.exit	= gtp_net_exit,
	.id	= &gtp_net_id,
	.size	= sizeof(struct gtp_net),
};

int rpl_gtp_init_module(void)
{
	int err;

	err = rtnl_link_register(&gtp_link_ops);
	if (err < 0)
		goto error_out;

	err = register_pernet_subsys(&gtp_net_ops);
	if (err < 0)
		goto unreg_rtnl_link;

	pr_info("GTP-LWT module with tunnel metadata support\n");
	return 0;

unreg_rtnl_link:
	rtnl_link_unregister(&gtp_link_ops);
error_out:
	pr_err("error loading GTP module loaded\n");
	return err;
}

void rpl_gtp_cleanup_module(void)
{
	rtnl_link_unregister(&gtp_link_ops);
	unregister_pernet_subsys(&gtp_net_ops);

	pr_info("GTP-LWTmodule unloaded\n");
}
