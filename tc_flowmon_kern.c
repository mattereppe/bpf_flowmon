/* SPDX-License-Identifier: GPL-2.0 */

/* Detect BCC vs libbpf mode
 */
#ifdef BCC_SEC
#define __BCC__
#endif

#include "common.h"
#include <string.h>
#include <linux/bpf.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>		// struct ethhdr
#include <linux/pkt_cls.h>
/*#include <linux/time.h>*/
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <linux/ip.h>
#ifndef __BCC__
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> 		// bpf_ntohs
#include <iproute2/bpf_elf.h>
#endif

#ifdef _DEBUG_
#define bpf_debug(fmt, ...)                          \
    ({                                               \
        char ____fmt[] = fmt;                        \
        bpf_trace_printk(____fmt, sizeof(____fmt),   \
            ##__VA_ARGS__);                          \
    })
#else
#define bpf_debug(fmt, ...)                          \
{}
#endif

/* Exit return codes */
#define EXIT_OK 		 0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL		 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION	 2
#define EXIT_FAIL_XDP		30
#define EXIT_FAIL_BPF		40

/* TCP options */
#define TCP_OPT_END	0
#define TCP_OPT_NONE	1
#define TCP_OPT_MSS	2
#define TCP_OPT_WNDWS	3
#define TCP_OPT_SACKP	4
#define TCP_OPT_SACK	5
#define TCP_OPT_TS	8

struct tcp_opt_none {
	__u8 type;
};

struct tcp_opt_mss {
	__u8 type;
	__u8 len;
	__u16 data;
};

struct tcp_opt_wndw_scale {
	__u8 type;
	__u8 len;
	__u8 data;
};

struct tcp_opt_sackp {
	__u8 type;
	__u8 len;
};

/* Bypassing the verifier check is not simple with variable data,
 * but for now I don't need to parse sack data.
 */
struct tcp_opt_sack {
	__u8 type;
	__u8 len;
//	__u32 data[8];
};

struct tcp_opt_ts {
	__u8 type;
	__u8 len;
	__u32 data[2];
};

struct tcpopt {
	struct tcp_opt_mss *op_mss;
	struct tcp_opt_wndw_scale *op_wndw_scale;
	struct tcp_opt_sackp *op_sackp;
	struct tcp_opt_sack *op_sack;
	struct tcp_opt_ts *op_ts;
};

struct optvalues {
	__u16* mss;
	__u8* wndw_scale;
};

/* TODO: Improve performance by using multiple per-cpu hash maps.
 */
#ifdef __BCC__
BPF_ARRAY(fl_stats, __u32, NBINS); /* TODO */
#else /* ifdef __BCC__ */
/* The standard way. Fully compatible with all tools, but 
 * needs an external program to be pinned and shared between
 * multiple program instances.
 */
/*
 * struct bpf_map_def SEC("maps") flowmon_stats = {
 * 	.type = BPF_MAP_TYPE_HASH,
 * 	.key_size = sizeof(struct flow_id),
 * 	.value_size = sizeof(struct flow_info),
 * 	.max_entries = MAXFLOWS,
 * 	.map_flags = BPF_ANY
 * };
 */

/* The iproute2 way. This provides additional metadata for
 * iproute2, especially to automatically pin the map and
 * share it with among instances.
 * See the full description from the Cilium project:
 * https://docs.cilium.io/en/latest/bpf/
 */
struct bpf_elf_map SEC("maps") flowmon_stats = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(struct flow_id),
    .size_value     = sizeof(struct flow_info),
    .pinning        = PIN_GLOBAL_NS, /* Alternatives: PIN_OBJECT_NS, PIN_NONE */
    .max_elem       = MAXFLOWS,
};

#endif /* ifdef __BCC__ */

#ifndef __BCC__
#define VLAN_MAX_DEPTH 4		/* Max number of VLAN headers parsed */
#endif

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
        void *pos;
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
        return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
                  h_proto == bpf_htons(ETH_P_8021AD));
}

#ifndef __BCC__
/*
 *      struct vlan_hdr - vlan header
 *      @h_vlan_TCI: priority and VLAN ID
 *      @h_vlan_encapsulated_proto: packet type ID or len
 *
 *      It is not clear why this structure is not present in
 *      the user header files. It is only present in kernel
 *      headers, but I cannot include that file otherwise
 *      I get other errors.
 */
struct vlan_hdr {
        __be16  h_vlan_TCI;
        __be16  h_vlan_encapsulated_proto;
};
#endif

/*
 * Struct icmphdr_common represents the common part of the icmphdr and icmp6hdr
 * structures.
 */
struct icmphdr_common {
        __u8	type;
	__u8    code;
	__sum16 cksum;
};


/* Parse the Ethernet header and return protocol.
 * Ignore VLANs.
 *
 * Protocol is returned in network byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ethhdr **ethhdr)
{
       struct ethhdr *eth = nh->pos;
        int hdrsize = sizeof(*eth);
        struct vlan_hdr *vlh;
        __u16 h_proto;
        int i;

        /* Byte-count bounds check; check if current pointer + size of header
         * is after data_end.
         */
        if (nh->pos + hdrsize > data_end)
                return -1;

        nh->pos += hdrsize;
        *ethhdr = eth;
        vlh = nh->pos;
        h_proto = eth->h_proto;

        /* Use loop unrolling to avoid the verifier restriction on loops;
         * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
         */
        #pragma unroll
        for (i = 0; i < VLAN_MAX_DEPTH; i++) {
                if (!proto_is_vlan(h_proto))
                        break;

                if ( (void *)(vlh + 1) > data_end)
                        break;

                h_proto = vlh->h_vlan_encapsulated_proto;
                vlh++;
        }

        nh->pos = vlh;
        return bpf_ntohs(h_proto); /* host-byte-order */


}

#ifdef __FLOW_IPV6__
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = nh->pos;

	/* Pointer-arithmetic bounds check; pointer +1 points to after end of
	 * thing being pointed to. We will be using this style in the remainder
	 * of the tutorial.
	 */
 	if ( (void *)(ip6h + 1) > data_end)
		return -1;

	nh->pos = ip6h + 1;
	*ip6hdr = ip6h;

	return ip6h->nexthdr;
}
#endif /* ifdef __FLOW_IPV6__ */

#ifdef __FLOW_IPV4__
static __always_inline int parse_iphdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if (iph + 1 > data_end)
		return -1;

	hdrsize = iph->ihl * 4;
	// Sanity check packet field is valid/
	if(hdrsize < sizeof(iph))
		return -1;

	// Variable-length IPv4 header, need to use byte-based arithmetic 
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}
#endif /* ifdef __FLOW_IPV4__ */

/* Not needed when only the common part of the ICMP/ICMP6 header
 * is parsed (see parse_icmphdr_common() below.
 */
/*
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6h = nh->pos;

	if (icmp6h + 1 > data_end)
		return -1;

	nh->pos   = icmp6h + 1;
	*icmp6hdr = icmp6h;

	return bpf_ntohs(icmp6h->icmp6_type);
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
					 void *data_end,
					 struct icmphdr **icmphdr)
{
	struct icmphdr *icmph = nh->pos;

	if (icmph + 1 > data_end)
		return -1;

	nh->pos  = icmph + 1;
	*icmphdr = icmph;

	return bpf_ntohs(icmph->type);
}
*/

/* This parses the common fields to ICMP/ICMP6 header.
 */
static __always_inline int parse_icmphdr_common(struct hdr_cursor *nh,
						void *data_end,
						struct icmphdr_common **icmphdr)
{
	struct icmphdr_common *h = nh->pos;

	if (h + 1 > data_end)
		return -1;

	nh->pos  = h + 1;
	*icmphdr = h;

	return bpf_ntohs(h->type);
}

/*
 * parse_udphdr: parse the udp header and return the length of the udp payload
 */
static __always_inline int parse_udphdr(struct hdr_cursor *nh,
					void *data_end,
					struct udphdr **udphdr)
{
	int len;
	struct udphdr *h = nh->pos;

	if (h + 1 > data_end)
		return -1;

	nh->pos  = h + 1;
	*udphdr = h;

	len = bpf_ntohs(h->len) - sizeof(struct udphdr);
	if (len < 0)
		return -1;

	return len;
}

#ifdef __FLOW_TCP_OPTS__
static __always_inline int tcpopt_type(void * tcph, unsigned int offset, void *data_end)
{
	struct tcp_opt_none *opn;

	opn = (struct tcp_opt_none *)(tcph+offset);

	if ( opn+1 > data_end )
		return -1;
	else
		return opn->type;
	
}

/*
 * parse_tcpopt: parse tcp options and returns the length
 * of the options.
 * N.B. This implementation works, but it is buggy becase it only
 * parses the first 5 options. Unfortunately, the combination of 
 * case switches leads to an unmanageable number of alternative
 * execution branches that the internal verifier cannot sustain.
 * I could reach 10 loops with the simpler options, but this does
 * not work with all possible options. Alternative implementations
 * should be investigated to improve this part.
 * Update: I tried to copy the options to an array (with a union 
 * structure to manage access to words and bytes), but then I 
 * always got an error when trying to copy the values to the map
 * fields. Loading of the overall structure was far quicker, but 
 * I didn't find a solution for the copy.
 * Among the many errors I got when accessing the packet, out of 
 * boundary was among the most common. It may be due to a bug in
 * the bpf verifier, as noted by the following post:
 * https://mechpen.github.io/posts/2019-08-29-bpf-verifier/index.html
 */
static __always_inline int parse_tcpopt(struct tcphdr *tcph,
					void *data_end,
					struct optvalues value)
{
	unsigned short op_tot_len = 0;
	unsigned short last_op = 0;
	struct tcp_opt_mss *mss = 0;
	struct tcp_opt_wndw_scale *wndw_scale = 0;
	struct tcp_opt_sackp *sackp = 0;
	struct tcp_opt_sack *sack = 0;
	struct tcp_opt_ts *ts = 0;
	unsigned int offset = 20;
	__u8 type;

	op_tot_len = (tcph->doff - 5)*4;

	if( op_tot_len < 0 )
		return -1;
	
	if( (void *)(tcph+1)+op_tot_len > data_end )
		return -1;

	
	/* 10 loops is arbitrary, hoping this could cover most use-cases.
	 * A fixed boundary is required by the internal verifier.
	 */
	for(unsigned int i=0; i<5; i++)
	{
		type = tcpopt_type((void *) tcph, offset,data_end);
	
		switch ( type ) {
			case TCP_OPT_END:
				last_op = 1;
			case TCP_OPT_NONE:
				offset++;
				op_tot_len--;
				break;
			case TCP_OPT_MSS:
				mss = (struct tcp_opt_mss *)((void *)tcph+offset);
				if( mss+1 > data_end )
					return -1;
				offset+=mss->len;
				op_tot_len-=mss->len;
				*value.mss = ntohs(mss->data);
				break;
			case TCP_OPT_WNDWS:
				wndw_scale = (struct tcp_opt_wndw_scale *)((void *)tcph+offset);
				if( wndw_scale+1 > data_end )
					return -1;
				offset+=wndw_scale->len;
				op_tot_len-=wndw_scale->len;
				*value.wndw_scale = wndw_scale->data;
				break;
			case TCP_OPT_SACKP:
				sackp = (struct tcp_opt_sackp *)((void *)tcph+offset);
				if( sackp+1 > data_end)
					return -1;
				offset+=sackp->len;
				op_tot_len-=sackp->len;
				// No data read for this option
				break;
			case TCP_OPT_SACK:
				sack = (struct tcp_opt_sack *)((void *)tcph+offset);
				if( sack+1 > data_end)
					return -1;
				offset+=sack->len;
				op_tot_len-=sack->len;
				// No data read for this option
				break;
			case TCP_OPT_TS:
				ts = (struct tcp_opt_ts *)((void *)tcph+offset);
				if( ts+1 > data_end)
					return -1;
				offset+=ts->len;
				op_tot_len-=ts->len;
				// No data read for this option
				break;
			default:
				last_op = 1;
				break;

		}

		if ( last_op || op_tot_len <= 0)
			break;
	}

	return op_tot_len;
}
#endif /* ifdef __FLOW_TCP_OPTS__ */

/*
 * parse_tcphdr: parse and return the length of the tcp header
 */
static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
					void *data_end,
					struct tcphdr **tcphdr)
{
	int len;
	struct tcphdr *h = nh->pos;

	if (h + 1 > data_end)
		return -1;

	len = h->doff * 4;
	// Sanity check packet field is valid 
	if(len < sizeof(h))
		return -1;

	// Variable-length TCP header, need to use byte-based arithmetic 
	if (nh->pos + len > data_end)
		return -1;

	nh->pos += len;
	*tcphdr = h;

	return data_end - nh->pos;
}

#ifdef __FLOW_IPV4__
/* Parse the headers and look for the parameters that identify the flow.
 */
static __always_inline int process_ip_header(struct hdr_cursor *nh,
					void *data_end,
					struct iphdr **iph,
					struct flow_id *key)
{
	int proto;

	if( (proto = parse_iphdr(nh, data_end, iph)) < 0)
		return proto;

	key->daddr.v4 = (*iph)->daddr;
	key->saddr.v4 = (*iph)->saddr;
	key->proto = proto;

	return proto;
}
#endif /* ifdef __FLOW_IPV4__ */

#ifdef __FLOW_IPV6__
static __always_inline int process_ipv6_header(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr,
					struct flow_id *key)
{
	int proto;
	
	if( (proto = parse_ip6hdr(nh, data_end, ip6hdr)) < 0)
		return proto;

	/* TODO: copy ipv6 addresses in the key, once this field supports 
	 * IPv6 flows. 
	 * For now, an error is returned because this protocol is not
	 * supported.
	 */
	memcpy(key->saddr.v6, (*ip6hdr)->saddr.s6_addr, 16);
	memcpy(key->daddr.v6, (*ip6hdr)->daddr.s6_addr, 16);
	key->proto = proto;

	return proto;
}
#endif

			
static __always_inline int process_udp_header(struct hdr_cursor *nh,
					void *data_end,
					struct udphdr **udphdr,
					struct flow_id *key)
{
	int len;

	if( (len = parse_udphdr(nh, data_end, udphdr)) < 0 )
		return len;

	key->sport = bpf_ntohs((*udphdr)->source);
	key->dport = bpf_ntohs((*udphdr)->dest);

	return len;
}

static __always_inline int process_tcp_header(struct hdr_cursor *nh,
					void *data_end,
					struct tcphdr **tcphdr,
					struct flow_id *key)
{
	int len;

	if( (len = parse_tcphdr(nh, data_end, tcphdr)) < 0 )
		return len;

	key->sport = bpf_ntohs((*tcphdr)->source);
	key->dport = bpf_ntohs((*tcphdr)->dest);

	return len;
}

static __always_inline int process_icmp_header(struct hdr_cursor *nh,
						void *data_end,
						struct icmphdr_common **icmphdr,
						struct flow_id *key)
{
	int len;

	if( (len = parse_icmphdr_common(nh, data_end, icmphdr)) < 0 )
		return len;

	/* This is a totally arbitrary association with no real meaning
	 * for the names. 
	 * TODO: check if this works for the monitoring purposes.
	 */
	key->sport = ((*icmphdr)->type);
	key->dport = ((*icmphdr)->code);

	return len;
}

static __always_inline int update_frame_stats(struct flow_info *value, __u64 ts)
{
	value->pkts++;
	if( value->first_seen == 0 ) {
		value->first_seen = ts;
		value->last_seen = ts;
		value->jitter = 0;
	}
	else
		value->jitter += ts - value->last_seen;
	value->last_seen = ts;

	return 1;
}

static __always_inline int update_ip_stats(struct flow_info *value, void *iph)
{
	int idx;
	int fl, len;
	__u8 tos, ttl;
	struct iphdr *ip4h;
	struct ipv6hdr *ip6h;

	ip4h = (struct iphdr *) iph;
	ip6h = (struct ipv6hdr *) iph;
	fl = 0;

	value->version = ip4h->version;

	/* Here we remove the dependency on the 
	 * IP version, so in the following the same
	 * code applies to both versions.
	 */
	if ( ip4h->version == 4 )
	{
		tos = ip4h->tos;
		len = ntohs(ip4h->tot_len);
		ttl = ip4h->ttl;
	}
	else
	{
		tos = ip6h->priority;
		for(int i=0; i<3; i++)
		{
			fl |= ip6h->flow_lbl[i];
			if( i <2 )
				fl <<= 8;
		}
		len = ntohs(ip6h->payload_len) + 40;
		// TODO: Manage Jumbo payload (payload length = 0)
		ttl = ip6h->hop_limit;
	}
	
	/* TODO: Here we can detect covert channels in
	 * the IP header.	
	 */
	value->fl = fl;
	value->tos = tos;

	value->bytes += len;
	if( len < value->min_pkt_len) 
		value->min_pkt_len = len;
	if( len > value->max_pkt_len )
		value->max_pkt_len = len;
	switch ( len ) {
		case 0 ... 127:
			idx = 0;
			break;
		case 128 ... 255:
			idx = 1;
			break;
		case 256 ... 511:
			idx = 2;
			break;
		case 512 ... 1023:
			idx = 3;
			break;
		case 1024 ... 1513:
			idx = 4;
			break;
		default:
			idx = 5;
	}
	value->pkt_size_hist[idx]++;

	if( ttl < value->min_ttl) 
		value->min_ttl = ttl;
	if( ttl > value->max_ttl )
		value->max_ttl = ttl;
	switch ( ttl ) {
		case 1:
			idx = 0;
			break;
		case 2 ... 5:
			idx = 1;
			break;
		case 6 ... 32:
			idx = 2;
			break;
		case 33 ... 64:
			idx = 3;
			break;
		case 65 ... 96:
			idx = 4;
			break;
		case 97 ... 128:
			idx = 5;
			break;
		case 129 ... 160:
			idx = 6;
			break;
		case 161 ... 192:
			idx = 7;
			break;
		case 193 ... 224:
			idx = 8;
			break;
		case 225 ... 255:
			idx = 9;
	}
	value->pkt_ttl_hist[idx]++;


	return len;
}

static __always_inline int update_tcp_stats(struct flow_info *value, 
						void *iph,
						struct tcphdr *tcph, 
						int tcp_len,
						void *data_end)
{
	__u16 flags;
	__u32 wndw;
	__u32 seq;
	__be16 id;
	int seg_len;
#ifdef __FLOW_TCP_OPTS__
	unsigned int op_tot_len;
#endif

	union tcp_word_hdr *twh = (union tcp_word_hdr *) tcph;
	flags = ntohl(twh->words[3] & htonl(0x00FF0000)) >> 16;

	value->cumulative_flags |= flags;

	/* The following code needs to read the options!
	 * Otherwise wind_scale would not be known.
	 */
	wndw = ntohs(tcph->window) << value->wndw_scale;
	if( wndw < value->min_win_bytes )
		value->min_win_bytes = wndw;
	if( wndw > value->max_win_bytes)
		value->max_win_bytes = wndw;
	
#ifdef __FLOW_TCP_OPTS__
	/* Scan and process options. This part should be skipped when
	 * the corresponding TCP fields are not required.
	 */
	struct optvalues values;
	values.mss = &value->mss;
	values.wndw_scale = &value->wndw_scale;
	op_tot_len=0;
	op_tot_len = parse_tcpopt(tcph, data_end, values);

	if( op_tot_len > 0 )
		bpf_debug("Unable to parse all options!\n");
#endif /* ifdef __FLOW_TCP_OPTS__ */


	/* This is a simplified implementation that does not cover every
	 * possible use cases. It only detects the retransmission of the last
	 * segment, but does not work when more segments are retransmitted.
	 *
	 * Note: this only detects duplicated segments, not duplicated TCP
	 * packets. For instance, this approach cannot detect duplicated SYN
	 * packets, duplicated ACK packets, and so on.
	 * Note2: this probably counts out-of-order segments as retransmissions
	 * (see below the notes).
	 *
	 * TODO: Understand if it is worth investigating a more precise method
	 * and how it would impact performance.
	 */
	struct iphdr *iph4 = (struct iphdr *) iph;
	if( iph4->version == 4 )
		/* No implementation available for IPv6. */
	{
		seq = ntohl(tcph->seq);
		id = ntohs(iph4->id);
		seg_len = tcp_len - tcph->doff*4;
		if( seg_len < 0 )
		{
			bpf_debug("Err: tcp seg len %d\n",seg_len);
			return -1;
		}
	
		/* There are 3 conditions to verify:
		 * Condition 1: No ACK packet (segment length > 0)
		 * Condition 2: same seq previously seen
		 * Condition 3: different id of previous pkt;
		 * https://www.flowmon.com/en/blog/measuring-tcp-retransmissions-in-flowmon
		 *
		 * In practice, the seq refers to the first expected byte in the packet (if
		 * present), so we must compute the expected seq number and check whether
		 * the current seq is = or it is a previous value. We cannot simply check
		 * the prev seq, because after an ACK we have a segment with len > 0 but
		 * with the same seq as the previous ACK.
		 */
		if( seg_len > 0 &&
			seq < value->next_seq && 
			id != value->last_id )
		{
			(value->retr_pkts)++;
			value->retr_bytes += seg_len;
		}
		else
		{
			value->next_seq = seq + seg_len;
			value->last_id = id;
		}
	}

	/* Out-Of-Order packets.
	 * Detecting ooo packets is tricky, because they are packets that arrive 
	 * after a following SEQ has been seen. This is basically the same condition
	 * as retransmission, so it is challenging to distinguish between the two events.
	 * My idea is that this should be possible by building a sort of "map" for
	 * sequence number, which keeps track of which portion of the seq number space
	 * has been seen. If the current SEQ is before the expected SEQ, by looking
	 * at this map we could distinguish between retransmissions and ooo.
	 * The implementation is not trivial, and requires some test cases for 
	 * validation. For this reason, it is postponed, maybe to a thesis. In any
	 * case, it is necessary to understand if and how bpf tail calls can be
	 * used to manage the number of operations that are necessary to build all
	 * the necessary statistics, since the current code does not fit the limited
	 * size of the stack.
	 *
	 *                     SeqA             SeqB       SeqC
	 *                     |                |          |
	 *                     V                V          V 
	 * +-----+----+--------+-------+--------+-----+----+-----------+-------+-------+
	 * |     |    |        |///////|        |     |////|///////////|       |       |
	 * +-----+----+--------+-------+--------+-----+----+-----------+-------+-------+
	 *            A                A        A                      A
	 *            |                |        |                      |
	 *            Seq1             Seq2     Seq3                   Seq4 
	 *     
	 *  Let the following be the list of packets seen: Seq1, Seq2, Seq3, Seq4.
	 *  If the next packet is:
	 *  - SeqA: SeqA<Seq4, but this is out of order
	 *  - SeqB: SeqB<Seq4, and this is a retransmission
	 *  - SeqC: SeqC<Seq4, and this is again out-of-order
	 *  I don't see a trivial method to distinguish between retransmission and ooo,
	 *  if we don't create a map to store the current status. And I didn't consider
	 *  selective acknowlegement in my reasoning!
	 *
	 */

	return 1;
}

static __always_inline void init_info(struct flow_info *info)
{
	if( info ) {
		/* Initialize all fields that store min values. */
		info->min_pkt_len = 0xffff;
		info->min_ttl = 0xff;
		info->min_win_bytes = 0xffff;
		info->wndw_scale = 0;
		info->retr_pkts = 0;
		info->retr_bytes = 0;
	}
}

#ifdef __BCC__
BCC_SEC("flowmon")
#else
SEC("flowmon")
#endif
int  flow_label_stats(struct __sk_buff *skb)
{
	/* Preliminary step: cast to void*.
	 * (Not clear why data/data_end are stored as long)
	 */
	void *data_end = (void *)(long)skb->data_end;
	void *data     = (void *)(long)skb->data;
	__u32 len = 0;
	/* __u32 init_value = 1; */
	int eth_proto, ip_proto = 0;
	unsigned int ip_tot_len = 0;
	/* int eth_proto, ip_proto, icmp_type = 0; */
	struct flow_id key = { 0 }; 
	struct flow_info info = { 0 };
	struct flow_info *value = 0;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	void * iph; /* Generic pointer to iph4 or iph6 (see below) */
#ifdef __FLOW_IPV4__
	struct iphdr *iph4;
#endif /* __FLOW_IPV4__ */
#ifdef __FLOW_IPV6__
	struct ipv6hdr *iph6;
#endif /* __FLOW_IPV4__ */
	struct icmphdr_common *icmphdrc;
	struct tcphdr *tcphdr;
	struct udphdr *udphdr;

	__u64 ts;

	ts = bpf_ktime_get_ns();	
	
	/* Parse Ethernet header and verify protocol number. */
	nh.pos = data;
	len = data_end - data;
	eth = (struct ethhdr *)data;
	eth_proto = parse_ethhdr(&nh, data_end, &eth);


	/* Check a valid eth proto was found. */
	if ( eth_proto < 0 ) {
		bpf_debug("Unknown ethernet protocol/Too many nested VLANs.\n");
		return TC_ACT_OK; /* TODO: XDP_ABORT? */
	}

	/* Retrieve ip_proto, according to specific IP version. 
	 * TODO: read IP source/destination addresses.
	 */
	switch (eth_proto) {
#ifdef __FLOW_IPV4__
		case ETH_P_IP:
			if( (ip_proto = process_ip_header(&nh, data_end, &iph4, &key)) < 0 )
				return TC_ACT_OK; /* Should we drop in this case??? */
			iph = iph4;
			break;
#endif /* ifdef __FLOW_IPV4__ */
#ifdef __FLOW_IPV6__
		case ETH_P_IPV6:
			if( (ip_proto = process_ipv6_header(&nh, data_end, &iph6, &key)) < 0 ) 
				return TC_ACT_OK;
			iph = iph6;
			break;
#endif /* ifdef __FLOW_IPV6__ */
		default:
			/* This happens mostly for link-layer protocols. They are not
			 * considered in this implementation. 
			 */
			return TC_ACT_OK;
	}

	/* Read port numbers or equivalent fields for ICMP packets.
	 */
	switch (ip_proto) {
		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
			if( process_icmp_header(&nh, data_end, &icmphdrc, &key) < 0 )
				return TC_ACT_OK;
			break;
		case IPPROTO_TCP:
			if( process_tcp_header(&nh, data_end, &tcphdr, &key) < 0 )
				return TC_ACT_OK;
			break;
		case IPPROTO_UDP:
			if( process_udp_header(&nh, data_end, &udphdr, &key) < 0 )
				return TC_ACT_OK;
			break;
		default:
			/* TODO: cound how many packets/bytes are seen from
			 * unmanaged protocols, so we can understand the impact
			 * of such traffic. 
			 * Hints: a common line with IPPROTO_MAX may be used.
			 */
			return TC_ACT_OK;
	}


	/* Collect the required statistics. */
#ifdef __BCC__
	flowmon_stats.lookup(&key);
#else /* ifdef __BCC__ */
	value = bpf_map_lookup_elem(&flowmon_stats, &key); 
#endif /* ifdef __BCC__ */
	if ( !value )
	{
		init_info(&info);
		value = &info;
	}
	/* Makes no sense, since it should have been already initialized in the previous
	 * block, but this is one more issue of the run-time verifier.
	 */
	if ( value )
		value->ifindex = skb->ifindex;

	
	update_frame_stats(value, ts);
	
	ip_tot_len = update_ip_stats(value, iph);

	if ( ip_proto == IPPROTO_TCP ) {
		/* TODO: What happens in case options are present in IP? */
		/* TODO: IPv6 */
		int tcp_len = ip_tot_len - ((void *)tcphdr - iph);
		if( tcp_len < 20 )
			bpf_debug("Error: tcp length: %d\n", tcp_len);
		else
			update_tcp_stats(value, iph, tcphdr, tcp_len, data_end);
	}

#ifdef __BCC__
	/* TODO: check if this works or anything else is necessary */
	flowmon_stats.update(&key, value);
#else /* ifdef __BCC__ */
	bpf_map_update_elem(&flowmon_stats, &key, value, BPF_ANY); 
#endif /* ifdef __BCC__ */


	return TC_ACT_OK;
}

#ifndef __BCC__
char _license[] SEC("license") = "GPL";
#endif
