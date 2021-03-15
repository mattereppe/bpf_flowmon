#ifndef _COMMON_H_
#define _COMMON_H_

#include <linux/types.h>

/* Max number of flows that can be
 *	monitored. 
 */
#define MAXFLOWS		1024 

/* Define the identifier for each flow. 
 *	Fields are currently sized for IPv4. 
 *	TODO: add support for IPv6.
 */
#ifdef __FLOW_IPV4__
struct flow_id {
		__be32	saddr;
		__be32	daddr;
		__be16	sport;			/* "id" for ICM Echo request/reply */
		__be16	dport;			/* "Seq" for ICMP Echo request/reply */
		__u8	proto;			/* This position is better for padding. */
};
#endif
#ifdef __FLOW_IPV6__
struct flow_id {
		__u8	saddr[16];
		__u8	daddr[16];
		__u8	proto;
		__be16	sport;			/* "id" for ICM Echo request/reply */
		__be16	dport;			/* "Seq" for ICMP Echo request/reply */
};
#endif

/* Define the data collected for each flow.
 *	TODO: add support for more statistics.
 */
struct flow_info {
	/* Generic flow information (for all protocols) */
	__u64	first_seen;		/* Epoch of the first packet of this flow (ns). */
	__u64	last_seen;	  	/* Epoch of the last packet seen so far (ns). */
	__u64	jitter;			/* Cumulative delays between packets. */
	__u32	pkts;		    	/* Cumulative number of packets. */
	__u32	ifindex;		/* Capture interface. */

	/* IP-related filds and measurements. */
	__u8 	version;		/* Version (4/6) */
	__u8	tos;		   	/* TOS/DSCP (IPv4) or Traffic Class (IPv6). */	
	__u32	fl;			/* Flow label (IPv6 only). */
	__u32	bytes;		    	/* Cumulative number of bytes. */
	__u16	min_pkt_len;	 	/* Smallest IP packet seen in the flow. */
	__u16	max_pkt_len; 		/* Biggest IP packet seen in the flow. */
	__u16	pkt_size_hist[6];	/* [0]: pkts up to 128 bytes;
					 * [1]: pkts from 128 to 256 bytes;
					 * [2]: pkts from 256 to 512 bytes;
					 * [3]: pkts from 512 to 1024 bytes;
					 * [4]: pkts from 1024 to 1514 bytes;
					 * [5]: pkts over 1514 bytes.
					 */
	__u8	min_ttl;		/* Min TTL (IPv4) or Hop Limit (IPv6). */
	__u8	max_ttl;		/* Max TTL (IPv4) or Hop Limit (IPv6). */
	__u16	pkt_ttl_hist[10];	/* [0]: pkts with TTL=1;
					 * [1]: pkts with TTL>1 and TTL<=5;
					 * [2]: packets with TTL > 5 and <= 32;
					 * [3]: packets with TTL > 32 and <= 64;
					 * [4]: packets with TTL > 64 and <= 96;
					 * [5]: packets with TTL > 96 and <= 128;
					 * [6]: packets with TTL > 128 and <= 160;
					 * [7]: packets with TTL > 160 and <= 192;
					 * [8]: packets with TTL > 192 and <= 224;
					 * [9]: packets with TTL > 224 and <= 255.
					 */

	/* TCP-related fields. */
	__u32	last_seq;		/* Last sequence number seen (used for computing retransmissions. */
	__u8	cumulative_flags;	/* Cumulative TCP flags seen in all packets so far. */
	__u16	retr_pkts;		/* Total number of retrasmitted packets. */
	__u32	retr_bytes;		/* Total number of retransmitted bytes. */
	__u16	ooo_pkts;		/* Total number of out-of-order packets. */
	__u32	ooo_bytes;		/* Total number of out-of-order bytes. */
	__u32	min_win_bytes;		/* Min TCP Window. */
	__u32	max_win_bytes;		/* Max TCP Window. */
	__u16	mss;			/* TCP Max Segment Size. */
	__u8	wndw_scale;		/* TCP Window Scale. */

	/* Other NetFlow or IPFIX fields are L7- or mgmt specifics and are not collected through packets. */
};

/* TODO: Wanna use different maps for IPv6? This would save some space in 
 * the key for IPv4 flows.
 */
struct map_fds {
	int ingress; /* The fd for the map holding incoming packets. */
	int egress; /* The fd for the map holding outcoming packets. */
};

/* Exit return codes */
#define EXIT_OK                  0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL                1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION         2
#define EXIT_FAIL_XDP           30
#define EXIT_FAIL_BPF           40

#endif /* _COMMON_H_ */
