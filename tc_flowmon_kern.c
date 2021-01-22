/* SPDX-License-Identifier: GPL-2.0 */

/* Detect BCC vs libbpf mode
 */
#ifdef BCC_SEC
#define __BCC__
#endif

#include "common.h"
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

/*
struct bpf_map_def SEC("maps") fl_stats = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = MAXFLOWS,
	.map_flags = BPF_ANY
};
*/
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
        return bpf_ntohs(h_proto); /* host-byte-order */


}

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

	return iph->protocol;
}

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

/* Parse the headers and look for the parameters that identify the flow.
 */
static __always_inline int process_ip_header(struct hdr_cursor *nh,
					void *data_end,
					struct iphdr **iph,
					struct flow_id *key)
{
	int proto;

	bpf_debug("Checkpoint 1a");
	if( (proto = parse_iphdr(nh, data_end, iph)) < 0)
		return proto;
	bpf_debug("Checkpoint 1b : %x", proto);

	key->daddr = (*iph)->daddr;
	key->saddr = (*iph)->saddr;
	key->proto = proto;

	return proto;
}

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
	key->proto = proto;

	return -1;
}

			
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
	key->sport = bpf_ntohs((*icmphdr)->type);
	key->dport = bpf_ntohs((*icmphdr)->code);

	return len;
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
	/* int eth_proto, ip_proto, icmp_type = 0; */
	struct flow_id key = { 0 }; 
	struct flow_info info = { 0 };
	struct flow_info *value = 0;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	struct iphdr *iph4;
	struct ipv6hdr *iph6;
	struct icmphdr_common *icmphdrc;
	struct tcphdr *tcphdr;
	struct udphdr *udphdr;

	__u64 ts, te;

	ts = bpf_ktime_get_ns();	
	
	bpf_debug("Program invoked!");

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

	bpf_debug("Checkpoint 1 - eth proto: 0x%x",eth_proto);

	/* Retrieve ip_proto, according to specific IP version. 
	 * TODO: read IP source/destination addresses.
	 */
	switch (eth_proto) {
		case ETH_P_IP:
			if( (ip_proto = process_ip_header(&nh, data_end, &iph4, &key)) < 0 )
				return TC_ACT_OK; /* Should we drop in this case??? */
			break;
		case ETH_P_IPV6:
			if( (ip_proto = process_ipv6_header(&nh, data_end, &iph6, &key)) < 0 ) 
				return TC_ACT_OK;
			break;
		default:
			/* This happens mostly for link-layer protocols. They are not
			 * considered in this implementation. 
			 */
			return TC_ACT_OK;
	}

	bpf_debug("Checkpoint 2 - IP proto: 0x%x", ip_proto);
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


	bpf_debug("Checkpoint 3 - key.proto: %d", key.proto);

	/* Collect the required statistics. */
	value = bpf_map_lookup_elem(&flowmon_stats, &key); 
	if ( !value )
		value = &info;
	
	/* TODO: Add real statistics here. */
	value->pkts = 3;
	value->bytes = 46;

	bpf_debug("Checkpoint 4 - key.proto: %d", key.proto);

	 bpf_map_update_elem(&flowmon_stats, &key, value, BPF_ANY); 

	/*
	int k = 1;
	int v = 3;
	bpf_map_lookup_elem(&fl_stats, &k);
	bpf_map_update_elem(&fl_stats, &k, &v, BPF_ANY);
	*/

	bpf_debug("Just inserted something in the map...");

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
