/* SPDX-License-Identifier: GPL-2.0 */

/* Detect BCC vs libbpf mode
 */
#ifdef BCC_SEC
#define __BCC__
#endif

#include <linux/bpf.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>		// struct ethhdr
#include <linux/pkt_cls.h>
#include <linux/time.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
//#include <netinet/in.h>
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

/* Max number of flows that can be
 *	monitored. 
 */
#define MAXFLOWS		1024 

/* Exit return codes */
#define EXIT_OK 		 0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL		 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION	 2
#define EXIT_FAIL_XDP		30
#define EXIT_FAIL_BPF		40

/* Define the identifier for each flow. 
 *	Fields are currently sized for IPv4. 
 *	TODO: add support for IPv6.
 */
struct flow_id {
		__be32	saddr;
		__be32	daddr;
		__u8		proto;
		__be16	sport;			/* "id" for ICM Echo request/reply */
		__be16	dport;			/* "Seq" for ICMP Echo request/reply */
};

/* Define the data collected for each flow.
 *	TODO: add support for more statistics.
 */
struct flow_info {
	__u32		pkts;
	__u32		bytes;
};

/* TODO: Improve performance by using multiple per-cpu hash maps.
 */
#ifdef __BCC__
BPF_ARRAY(fl_stats, __u32, NBINS); /* TODO */
#else
struct bpf_map_def SEC("maps") flowmon_stats = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct flow_id),
	.value_size = sizeof(struct flow_info),
	.max_entries = MAXFLOWS,
	.map_flags = BPF_ANY
};
#endif

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
	   *  * structures.
	   *   */
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
        return h_proto; /* network-byte-order */


}

/* TODO: Add IPv6 support.
 */
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

	return bpf_ntohs(iph->protocol);
}

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

/* TODO: change this for debugging flows (if really necessary). 
static unsigned int print_map()
#ifdef _DEBUG_
{
	__u32 key = 0;
	__u32 *counter = 0;
	__u32 value = 0;
	
	for(unsigned int i=0;i<NBINS;i++)
	{
		counter = bpf_map_lookup_elem(&fl_stats, &key);
		if(counter)
			value=*counter;
		else
			value=0;
		bpf_debug("[%d]: %d\n", key, value);
		key += 1;
	} 
	return 0;
};
#else
{
	return 0;
};
#endif
*/

			
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
	__u32 init_value = 1;
	int eth_proto, ip_proto = 0;
	/* int eth_proto, ip_proto, icmp_type = 0; */
	struct flow_id flow = { 0 }; 
	struct hdr_cursor nh;
	struct ethhdr *eth;
	/* struct ipv6hdr* iph6; */
	__u64 ts, te;

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
		case ETH_P_IPV4:
			if( (ip_proto = parse_iphdr(&nh, data_end, &iph4)) < 0 )
				return TC_ACK_OK; /* Should we drop in this case??? */
			break;
		case ETH_P_IPV6:
			if( (ip_proto = parse_ip6hdr(&nh, data_end, &iph6)) < 0 ) 
				return TC_ACT_OK;
			break;
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
			if( parse_icmp(&nh, data_end, &icmphdr) < 0 )
				return TC_ACT_OK;
			break;
		case IPPROTO_TCP:
			if( parse_tcp(&nh, data_end, &tcphdr) < 0 )
				return TC_ACT_OK;
			break;
		case IPPROTO_UDP:
			if( parse_udp(&nh, data_end, &udphdr) < 0 )
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

	/*
#ifndef __BCC__
		bpf_map_lookup_elem(&fl_stats, &key);
#else
		fl_stats.lookup(&key);
#endif
	if(!counter)
#ifndef __BCC__
		bpf_map_update_elem(&fl_stats, &key, &init_value, BPF_ANY);
#else
		fl_stats.update(&key, &init_value);
#endif
	else
		__sync_fetch_and_add(counter, 1);

	print_map();
	*/
	  

	te = bpf_ktime_get_ns();
	bpf_debug("Time elapsed: %d", te-ts);
	
	return TC_ACT_OK;
}

#ifndef __BCC__
char _license[] SEC("license") = "GPL";
#endif
