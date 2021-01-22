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

/* Exit return codes */
#define EXIT_OK                  0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL                1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION         2
#define EXIT_FAIL_XDP           30
#define EXIT_FAIL_BPF           40

#endif /* _COMMON_H_ */
