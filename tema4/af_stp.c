// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/hashtable.h>

#include "stp.h"

MODULE_DESCRIPTION("SO2 Transport Protocol");
MODULE_AUTHOR("Student");
MODULE_LICENSE("GPL");

#define STP_HASH_BITS	8

struct stp_sock {
	struct sock sk;
	__be16 src_port;
	int ifindex;
	int bound;
	int connected;
	__be16 dst_port;
	unsigned char dst_addr[ETH_ALEN];
	struct hlist_node node;
};

struct stp_cb {
	__be16 src_port;
	unsigned char src_addr[ETH_ALEN];
};

struct stp_stats {
	atomic_t rx_pkts;
	atomic_t hdr_err;
	atomic_t csum_err;
	atomic_t no_sock;
	atomic_t no_buffs;
	atomic_t tx_pkts;
};

static struct stp_stats stats;
static DEFINE_HASHTABLE(stp_bind_table, STP_HASH_BITS);
static DEFINE_SPINLOCK(stp_lock);
static struct proc_dir_entry *stp_proc_entry;

static struct proto stp_proto = {
	.name		= STP_PROTO_NAME,
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct stp_sock),
};

static inline struct stp_sock *stp_sk(struct sock *sk)
{
	return (struct stp_sock *)sk;
}

static __u8 stp_compute_csum(const void *data, int len)
{
	const __u8 *p = data;
	__u8 csum = 0;
	int i;

	for (i = 0; i < len; i++)
		csum ^= p[i];

	return csum;
}

static struct stp_sock *stp_lookup(__be16 port, int ifindex)
{
	struct stp_sock *ssk;

	hash_for_each_possible(stp_bind_table, ssk, node, ntohs(port)) {
		if (ssk->src_port == port &&
		    (ssk->ifindex == 0 || ssk->ifindex == ifindex)) {
			sock_hold(&ssk->sk);
			return ssk;
		}
	}

	return NULL;
}

static int stp_rcv(struct sk_buff *skb, struct net_device *dev,
		   struct packet_type *pt, struct net_device *orig_dev)
{
	struct stp_hdr *shdr;
	struct stp_sock *ssk;
	struct stp_cb *cb;
	int pkt_len;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		return NET_RX_DROP;

	if (skb->len < sizeof(struct stp_hdr)) {
		atomic_inc(&stats.hdr_err);
		goto drop;
	}

	shdr = (struct stp_hdr *)skb->data;
	pkt_len = ntohs(shdr->len);

	if (pkt_len < (int)sizeof(struct stp_hdr) || pkt_len > skb->len) {
		atomic_inc(&stats.hdr_err);
		goto drop;
	}

	if (shdr->dst == 0 || shdr->src == 0) {
		atomic_inc(&stats.hdr_err);
		goto drop;
	}

	if (stp_compute_csum(skb->data, pkt_len) != 0) {
		atomic_inc(&stats.csum_err);
		goto drop;
	}

	spin_lock_bh(&stp_lock);
	ssk = stp_lookup(shdr->dst, dev->ifindex);
	spin_unlock_bh(&stp_lock);

	if (!ssk) {
		atomic_inc(&stats.no_sock);
		goto drop;
	}

	/* Connected sockets only accept packets from the connected host */
	if (ssk->connected &&
	    (ssk->dst_port != shdr->src ||
	     memcmp(ssk->dst_addr, eth_hdr(skb)->h_source, ETH_ALEN) != 0)) {
		sock_put(&ssk->sk);
		atomic_inc(&stats.no_sock);
		goto drop;
	}

	cb = (struct stp_cb *)skb->cb;
	cb->src_port = shdr->src;
	memcpy(cb->src_addr, eth_hdr(skb)->h_source, ETH_ALEN);

	skb_pull(skb, sizeof(struct stp_hdr));
	skb_trim(skb, pkt_len - sizeof(struct stp_hdr));

	if (sock_queue_rcv_skb(&ssk->sk, skb) < 0) {
		atomic_inc(&stats.no_buffs);
		sock_put(&ssk->sk);
		goto drop;
	}

	atomic_inc(&stats.rx_pkts);
	sock_put(&ssk->sk);
	return NET_RX_SUCCESS;

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static struct packet_type stp_packet_type = {
	.type	= htons(ETH_P_STP),
	.func	= stp_rcv,
};

static int stp_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct stp_sock *ssk;

	if (!sk)
		return 0;

	ssk = stp_sk(sk);

	spin_lock_bh(&stp_lock);
	if (ssk->bound)
		hash_del(&ssk->node);
	spin_unlock_bh(&stp_lock);

	sock_orphan(sk);
	skb_queue_purge(&sk->sk_receive_queue);
	sock->sk = NULL;
	sock_put(sk);

	return 0;
}

static int stp_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	struct sockaddr_stp *sas = (struct sockaddr_stp *)addr;
	struct stp_sock *ssk = stp_sk(sock->sk);
	struct stp_sock *existing;
	u32 key;

	if (sas->sas_family != AF_STP)
		return -EINVAL;

	key = ntohs(sas->sas_port);

	spin_lock_bh(&stp_lock);

	hash_for_each_possible(stp_bind_table, existing, node, key) {
		if (existing->src_port == sas->sas_port) {
			spin_unlock_bh(&stp_lock);
			return -EADDRINUSE;
		}
	}

	ssk->src_port = sas->sas_port;
	ssk->ifindex = sas->sas_ifindex;
	ssk->bound = 1;
	hash_add(stp_bind_table, &ssk->node, key);

	spin_unlock_bh(&stp_lock);

	return 0;
}

static int stp_connect(struct socket *sock, struct sockaddr *addr,
		       int addr_len, int flags)
{
	struct sockaddr_stp *sas = (struct sockaddr_stp *)addr;
	struct stp_sock *ssk = stp_sk(sock->sk);

	ssk->dst_port = sas->sas_port;
	memcpy(ssk->dst_addr, sas->sas_addr, ETH_ALEN);
	ssk->connected = 1;

	return 0;
}

static int stp_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
	struct stp_sock *ssk = stp_sk(sk);
	struct sockaddr_stp *addr = NULL;
	struct sockaddr_stp connected_addr;
	struct sk_buff *skb;
	struct stp_hdr *shdr;
	struct net_device *dev;
	int total_len, err;

	if (msg->msg_name) {
		addr = (struct sockaddr_stp *)msg->msg_name;
	} else if (ssk->connected) {
		connected_addr.sas_family = AF_STP;
		connected_addr.sas_port = ssk->dst_port;
		connected_addr.sas_ifindex = 0;
		memcpy(connected_addr.sas_addr, ssk->dst_addr, ETH_ALEN);
		addr = &connected_addr;
	} else {
		return -EDESTADDRREQ;
	}

	if (ssk->ifindex)
		dev = dev_get_by_index(sock_net(sk), ssk->ifindex);
	else if (addr->sas_ifindex)
		dev = dev_get_by_index(sock_net(sk), addr->sas_ifindex);
	else
		return -ENODEV;

	if (!dev)
		return -ENODEV;

	total_len = sizeof(struct stp_hdr) + len;

	skb = sock_alloc_send_skb(sk,
				  LL_RESERVED_SPACE(dev) + total_len,
				  msg->msg_flags & MSG_DONTWAIT, &err);
	if (!skb) {
		dev_put(dev);
		return err;
	}

	skb_reserve(skb, LL_RESERVED_SPACE(dev));
	skb_reset_network_header(skb);

	shdr = (struct stp_hdr *)skb_put(skb, sizeof(struct stp_hdr));
	shdr->dst = addr->sas_port;
	shdr->src = ssk->src_port;
	shdr->len = htons(total_len);
	shdr->flags = 0;
	shdr->csum = 0;

	err = memcpy_from_msg(skb_put(skb, len), msg, len);
	if (err < 0) {
		kfree_skb(skb);
		dev_put(dev);
		return err;
	}

	shdr->csum = stp_compute_csum(skb_network_header(skb), total_len);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_STP);

	err = dev_hard_header(skb, dev, ntohs(skb->protocol),
			      addr->sas_addr, dev->dev_addr, skb->len);
	if (err < 0) {
		kfree_skb(skb);
		dev_put(dev);
		return err;
	}

	err = dev_queue_xmit(skb);
	dev_put(dev);

	if (err >= 0) {
		atomic_inc(&stats.tx_pkts);
		return len;
	}

	return err;
}

static int stp_recvmsg(struct socket *sock, struct msghdr *msg, size_t len,
		       int flags)
{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	int copied, err;

	skb = skb_recv_datagram(sk, flags, flags & MSG_DONTWAIT, &err);
	if (!skb)
		return err;

	copied = min_t(int, skb->len, len);

	err = skb_copy_datagram_msg(skb, 0, msg, copied);
	if (err < 0) {
		skb_free_datagram(sk, skb);
		return err;
	}

	if (msg->msg_name) {
		struct sockaddr_stp *sas = msg->msg_name;
		struct stp_cb *cb = (struct stp_cb *)skb->cb;

		sas->sas_family = AF_STP;
		sas->sas_port = cb->src_port;
		memcpy(sas->sas_addr, cb->src_addr, ETH_ALEN);
		msg->msg_namelen = sizeof(struct sockaddr_stp);
	}

	skb_free_datagram(sk, skb);

	return copied;
}

static const struct proto_ops stp_ops = {
	.family		= PF_STP,
	.owner		= THIS_MODULE,
	.release	= stp_release,
	.bind		= stp_bind,
	.connect	= stp_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.getname	= sock_no_getname,
	.poll		= datagram_poll,
	.ioctl		= sock_no_ioctl,
	.listen		= sock_no_listen,
	.shutdown	= sock_no_shutdown,
	.sendmsg	= stp_sendmsg,
	.recvmsg	= stp_recvmsg,
	.mmap		= sock_no_mmap,
};

static int stp_create(struct net *net, struct socket *sock, int protocol,
		      int kern)
{
	struct sock *sk;

	if (sock->type != SOCK_DGRAM)
		return -ESOCKTNOSUPPORT;

	if (protocol != 0)
		return -EPROTONOSUPPORT;

	sk = sk_alloc(net, PF_STP, GFP_KERNEL, &stp_proto, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);
	sock->ops = &stp_ops;

	return 0;
}

static const struct net_proto_family stp_family_ops = {
	.family	= PF_STP,
	.create	= stp_create,
	.owner	= THIS_MODULE,
};

static int stp_proc_show(struct seq_file *m, void *v)
{
	seq_puts(m, "RxPkts HdrErr CsumErr NoSock NoBuffs TxPkts\n");
	seq_printf(m, "%d %d %d %d %d %d\n",
		   atomic_read(&stats.rx_pkts),
		   atomic_read(&stats.hdr_err),
		   atomic_read(&stats.csum_err),
		   atomic_read(&stats.no_sock),
		   atomic_read(&stats.no_buffs),
		   atomic_read(&stats.tx_pkts));

	return 0;
}

static int stp_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, stp_proc_show, NULL);
}

static const struct proc_ops stp_proc_ops = {
	.proc_open	= stp_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int __init stp_init(void)
{
	int err;

	err = proto_register(&stp_proto, 1);
	if (err)
		return err;

	err = sock_register(&stp_family_ops);
	if (err)
		goto out_proto;

	stp_proc_entry = proc_create(STP_PROC_NET_FILENAME, 0,
				     init_net.proc_net, &stp_proc_ops);
	if (!stp_proc_entry) {
		err = -ENOMEM;
		goto out_sock;
	}

	dev_add_pack(&stp_packet_type);

	return 0;

out_sock:
	sock_unregister(PF_STP);
out_proto:
	proto_unregister(&stp_proto);
	return err;
}

static void __exit stp_exit(void)
{
	dev_remove_pack(&stp_packet_type);
	proc_remove(stp_proc_entry);
	sock_unregister(PF_STP);
	proto_unregister(&stp_proto);
}

module_init(stp_init);
module_exit(stp_exit);
