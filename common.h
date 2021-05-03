#ifndef _COMMON_H_
#define _COMMON_H_

#include <linux/types.h>

/* Max number of flows that can be
 *	monitored. 
 */
#define MAXFLOWS		65536 

/* Define the identifier for each flow. 
 * Managing IPv4 and IPv6 at the same time is not trivial. There are two 
 * approaches that can be used:
 * - duplicate the flow_id struct into the v4 and v6 version:
 *   - two different maps can be used, for each flow, saving memory for IPv4
 *   - all functions the take struct flow_id as input must be duplicated for
 *     the two versions
 *   - two sub-cases:
 *   1) the code is either compiled for IPv4 or IPv6
 *      - two programs run in parallel when both v4 and v6 flows are inspected
 *      - some functions are duplicated for each packet (ethernet parsing)
 *      - memory optimized in case of IPv4 flows
 *   2) the same program deals with IPv4 and IPv6 packets
 *      - no duplicated instructions
 *      - however, many functions are duplicated for the two cases, which may
 *        waste space in the stack
 * - use the same flow_id for both IPv4 and IPv6
 *   - memory saving is possible by providing the option for IPv4 only (__be32)
 *   - no unnecessary duplication of functions (all functions take the same struct
 *     flow_id as parameter)
 *   - no duplication of maps (memory is wasted for IPv4 flows)
 *   - no duplicated inspection instructions
 *
 * The second option facilitates code maintenance, at least during the development
 * phase. This is why it is now used, leaving the possibility to save memory with 
 * different struct flow_id for future comparison, it memory pops up to be a 
 * practical limitation during the tests.
 */

union ip_addr {
	__be32 v4;
#ifdef __FLOW_IPV6__
	__u8 v6[16];
#endif /* ifdef __FLOW_IPv6 */
};

struct flow_id {
		union ip_addr	saddr;
		union ip_addr	daddr;
		__be16		sport;	/* "id" for ICM Echo request/reply */
		__be16		dport;	/* "Seq" for ICMP Echo request/reply */
		__u8		proto;	/* This position is better for padding. */
} __attribute__((packed));

/* Define the data collected for each flow.
 *	TODO: add support for more statistics.
 *	ISSUE: too many instructions are necessary to parse TCP fields
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
	__u32	fl;			/* Flow label (IPv6). */
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
	__u32	next_seq;		/* Last sequence number seen (used for computing retransmissions. */
	__be16 	last_id;		/* Last ipv4 identification value for last_seq. */
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
/* Using the more correct option packed results in error
 * in the current code (due to usage of reference values).
 * This should be fixed before switching to this option.
 * } __attribute__((packed));
 */


/* Exit return codes */
#define EXIT_OK                  0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL                1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION         2
#define EXIT_FAIL_XDP           30
#define EXIT_FAIL_BPF           40

#endif /* _COMMON_H_ */
