#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <arpa/inet.h>

#include "common.h"

#define PINFILENAMELEN 40
extern int verbose;

#define MICROSEC_PER_SEC 1000000 /* 10^6 */
#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
#define FLOW_INACTIVE_TIMEOUT_SEC 10
#define FLOW_HANGOUT_TIMEOUT_SEC 3

/* Flow termination reasons:
 * 	1 - Flow terminated normally (connection closed).
 * 	2 - Flow terminated abnormally (connection reset).
 * 	3 - Timeout expired.
 * 	4 - Invalid or not present flow. This happens where there is not flow in the opposite direction. 
 */
#define FLOW_NOTERM 0
#define FLOW_TERM_CLOSED 1
#define FLOW_TERM_RESET 2
#define FLOW_TERM_TIMEOUT 3
#define FLOW_TERM_INVALID 4

/* TCP flags
 * (Unfortunately the macros in tcp.h apply to an entire tcp word.
 */
#define TCP_FLAG_ACK	0x0010
#define TCP_FLAG_PSH 	0x0008
#define TCP_FLAG_RST	0x0004
#define TCP_FLAG_SYN  	0x0002
#define TCP_FLAG_FIN  	0x0001

/* Operations on the flow list
 */
#define OP_PURGE	1 /* Dump and purge terminated and expired flows; count active flows. */
#define OP_COUNT 	2 /* Count all flows. */
#define OP_DUMP		3 /* Dump the current content of the flow table (uni-directional flows). */

#ifdef __FLOW_IPV6__
#define ADDRSTRLEN INET6_ADDRSTRLEN
#else
#define ADDRSTRLEN INET_ADDRSTRLEN
#endif /* ifdef __FLOW_IPV6__ */

/* #include <netinet/icmp6.h>
 * Missing definitions in linux/icmpv6.h.
 */
#define ND_ROUTER_SOLICIT           133
#define ND_ROUTER_ADVERT            134
#define ND_NEIGHBOR_SOLICIT         135
#define ND_NEIGHBOR_ADVERT          136
#define ND_REDIRECT                 137


struct flow_counters {
	unsigned int tot;
	unsigned int active;
	unsigned int purged; 
	unsigned int dumped;
};

/* Fix for IPv6 support before using again these functions.
static void _debug_print_flow_id(const struct flow_id *key)
{
	printf("Source addr: %d\n", key->saddr);
	printf("Dest   addr: %d\n", key->daddr);
	printf("Proto      : %d\n", key->proto);
	printf("Source port: %d\n", key->sport);
	printf("Dest   port: %d\n", key->dport);
}

static void _debug_dump_flow_id(const struct flow_id *key)
{
	const unsigned char *bin;

	bin = (const unsigned char*)key;
	printf("key dump: ");
	for(unsigned int i=0; i<16; i++)
		printf("%02x ", bin[i]);
	printf("\n");
}
*/

static unsigned int get_icmp_peer_type(const unsigned int type)
{
	switch ( type ) {
		case ICMP_ECHOREPLY:
			return ICMP_ECHO;
		case ICMP_ECHO:
			return ICMP_ECHOREPLY;
		case ICMP_TIMESTAMP:
			return ICMP_TIMESTAMPREPLY;
		case ICMP_TIMESTAMPREPLY:
			return ICMP_TIMESTAMP;
		case ICMP_INFO_REQUEST:
			return ICMP_INFO_REPLY;
		case ICMP_INFO_REPLY:
			return ICMP_INFO_REQUEST;
		case ICMP_ADDRESS:
			return ICMP_ADDRESSREPLY;
		case ICMP_ADDRESSREPLY:
			return ICMP_ADDRESS;
		case ICMPV6_ECHO_REQUEST:
			return ICMPV6_ECHO_REPLY;
		case ICMPV6_ECHO_REPLY:
			return ICMPV6_ECHO_REQUEST;
		case ICMPV6_MGM_QUERY:
			return ICMPV6_MGM_REPORT;
		case ICMPV6_MGM_REPORT:
			return ICMPV6_MGM_QUERY;
		case ICMPV6_NI_QUERY:
			return ICMPV6_NI_REPLY;
		case ICMPV6_NI_REPLY:
			return ICMPV6_NI_QUERY;
		case ICMPV6_DHAAD_REQUEST:
			return ICMPV6_DHAAD_REPLY;
		case ICMPV6_DHAAD_REPLY:
			return ICMPV6_DHAAD_REQUEST;
		case ICMPV6_MOBILE_PREFIX_SOL:
			return ICMPV6_MOBILE_PREFIX_ADV;
		case ICMPV6_MOBILE_PREFIX_ADV:
			return ICMPV6_MOBILE_PREFIX_SOL;
		/* netinet/icmpv6.h */
		case ND_ROUTER_SOLICIT:
			return ND_ROUTER_ADVERT;
		case ND_ROUTER_ADVERT:
			return ND_ROUTER_SOLICIT;
		case ND_NEIGHBOR_SOLICIT:
			return ND_NEIGHBOR_ADVERT;
		case ND_NEIGHBOR_ADVERT:
			return ND_NEIGHBOR_SOLICIT;
		default:
			return type;
	}
}

static void key_swap(const struct flow_id *key, struct flow_id *key2)
{
	int len;

	/* Note that struct flow_id is padded to 16B. 
	 * Unfortunately, padding bytes are used when computing the hash,
	 * so it is important to have all of them set to 0.
	 */
	memset((void *)key2, 0, sizeof(struct flow_id));

#ifdef __FLOW_IPV6__
	len = 16;
#else
	len = 4;
#endif /* ifdef __FLOW_IPV6__ */

	memcpy(key2->saddr.v6, key->daddr.v6, len);
	memcpy(key2->daddr.v6, key->saddr.v6, len);
	key2->proto = key->proto;
	switch ( key->proto) {
		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
			key2->sport = get_icmp_peer_type(key->sport);
			key2->dport = key->dport;
			break;
		default:
			key2->sport = key->dport;
			key2->dport = key->sport;
	}

}


/* Check whether the flow has to be removed, 
 * * but does not actually remove it.
 * Return values:
 * < 0: Error while checking the conditions.  
 * * > 0: Flow should be removed because expired.
 * 	(see reasons in the specific macros).
 * = 0: Flow should not be removed (still active).
 */
static int flow_to_remove(struct flow_id *key, struct flow_info *value)
{
	int err;
	unsigned long int last;

	/* Remove terminated or expired flows. */
	struct timespec now;

	/* Check whether the flow really exist or it is an empty flow.
	 */
	if(  value->last_seen == 0 )
		return FLOW_TERM_INVALID;

	/* Remove TCP flows according to status flags:
	 * - FIN ack is set
	 * - RST ack is set
	 */

	/* TODO: If additional traffic arrives after the first FIN/RST
	 * packet, such traffic is counted as an additional flow. To solve
	 * this issue, an INACTIVITY timeout should be provided and checked 
	 * before removing the flow.

	 *	if( (err = clock_gettime(CLOCK_BOOTTIME, &now) ) < 0 ) {
	 *		printf("Error getting current time: %d\n", errno);
	 *		return -1;
	 *	}
	 *	last = value->last_seen / NANOSEC_PER_SEC;
	 *
	 *	if(key->proto == IPPROTO_TCP)
	 *	{
	 *		if(now.tv_sec > (last + FLOW_HANGOUT_TIMEOUT_SEC ) &&
	 *			> value->cumulative_flags & TCP_FLAG_FIN) 
	 *			return FLOW_TERM_CLOSED;
	 *		if(now.tv_sec > (last + FLOW_HANGOUT_TIMEOUT_SEC ) &&
	 *			value->cumulative_flags & TCP_FLAG_RST) 
	 *			return FLOW_TERM_RESET;
	 *	}
	
	 * ... and remove the unnecessary code that follows!  */
	if(key->proto == IPPROTO_TCP)
	{
		if(value->cumulative_flags & TCP_FLAG_FIN) 
			return FLOW_TERM_CLOSED;
		if(value->cumulative_flags & TCP_FLAG_RST) 
			return FLOW_TERM_RESET;
	}

	/* Remove flows after inactivity timeout. */
	if( (err = clock_gettime(CLOCK_BOOTTIME, &now) ) < 0 ) {
		printf("Error getting current time: %d\n", errno);
		return -1;
	}
	last = value->last_seen / NANOSEC_PER_SEC;
	if( now.tv_sec > (last + FLOW_INACTIVE_TIMEOUT_SEC) )
		return FLOW_TERM_TIMEOUT;

	return FLOW_NOTERM;
}

/* Get the IP address family, from IP version in the header. 
 */
static __always_inline int get_family(const int ip_version)
{
	switch( ip_version ) {
		case 4:
			return AF_INET;
		case 6:
			return AF_INET6;
		default:
			return -1;
	}
}

/* Print the flow statistics.
 * TODO: This function should be replaced with a more appropriate 
 * output method.
 */
static void flow_print(struct flow_id *key, struct flow_info *value, FILE *fd)
{
	char ip_addr[ADDRSTRLEN];
	int family;

	family = get_family(value->version);

	/* Print the flow id. */
	if( inet_ntop(family, (const void *)(&(key->saddr)), ip_addr, ADDRSTRLEN) != 0 )
		fprintf(fd, "%s:%d",ip_addr, key->sport);
	fprintf(fd," -> ");
	if( inet_ntop(family, (const void *)(&(key->daddr)), ip_addr, ADDRSTRLEN) != 0 )
		fprintf(fd, "%s:%d",ip_addr, key->dport);
	fprintf(fd, " %d ",key->proto);

	/* Print statistics (very limited set so far). */
	fprintf(fd, "\t%d\t%d\t%lld\t%lld\n", value->pkts, value->bytes, value->first_seen, value->last_seen);
	
}

/* TODO: how to filter the information based on command-line string?
 */
static void flow_print_full(const struct flow_id *fkey, const struct flow_info *fvalue,
		const struct flow_id *bkey, const struct flow_info *bvalue, 
		FILE *fd)
{
	char ip_addr[ADDRSTRLEN];
	char if_name[IF_NAMESIZE];
	int family;

	family = get_family(fvalue->version);
	if( family < 0 ) {
		printf("Unknown family for IP version: %d\n", fvalue->version);
		return;
	}

	/* Print the flow id. */
	if( inet_ntop(family, (const void *)(&(fkey->saddr)), ip_addr, ADDRSTRLEN) != 0 )
		fprintf(fd, "%s\t",ip_addr);
	if( inet_ntop(family, (const void *)(&(fkey->daddr)), ip_addr, ADDRSTRLEN) != 0 )
		fprintf(fd, "%s\t",ip_addr);
	fprintf(fd, "%d\t", fkey->proto);
	fprintf(fd, "%hu\t", fkey->sport);
	fprintf(fd, "%hu\t", fkey->dport);

	/* Print statistics. */
	if( if_indextoname(fvalue->ifindex, if_name) == NULL )
		strcpy(if_name, "UNKNOWN");
	fprintf(fd, "%s\t",if_name); 	
	if( if_indextoname(bvalue->ifindex, if_name) == NULL )
		strcpy(if_name, "UNKNOWN");
	fprintf(fd, "%s\t",if_name); 	

	fprintf(fd, "%lld\t", fvalue->first_seen);
	fprintf(fd, "%lld\t", bvalue->first_seen);
	fprintf(fd, "%lld\t", fvalue->last_seen);
	fprintf(fd, "%lld\t", bvalue->last_seen);
	fprintf(fd, "%lld\t", fvalue->jitter);
	fprintf(fd, "%lld\t", bvalue->jitter);
	fprintf(fd, "%d\t", fvalue->pkts);
	fprintf(fd, "%d\t", bvalue->pkts);

	fprintf(fd, "%u\t", fvalue->version);
	fprintf(fd, "%u\t", bvalue->version);
	fprintf(fd, "%u\t", fvalue->fl);
	fprintf(fd, "%u\t", bvalue->fl);
	fprintf(fd, "%u\t", fvalue->tos);
	fprintf(fd, "%u\t", bvalue->tos);
	fprintf(fd, "%u\t", fvalue->bytes);
	fprintf(fd, "%u\t", bvalue->bytes);
	fprintf(fd, "%u\t", fvalue->min_pkt_len);
	fprintf(fd, "%u\t", bvalue->min_pkt_len);
	fprintf(fd, "%u\t", fvalue->max_pkt_len);
	fprintf(fd, "%u\t", bvalue->max_pkt_len);

	for(unsigned int i=0; i<6; i++)
		fprintf(fd, "%u\t", fvalue->pkt_size_hist[i]);
	for(unsigned int i=0; i<6; i++)
		fprintf(fd, "%u\t", bvalue->pkt_size_hist[i]);
	fprintf(fd, "%u\t", fvalue->min_ttl);
	fprintf(fd, "%u\t", bvalue->min_ttl);
	fprintf(fd, "%u\t", fvalue->max_ttl);
	fprintf(fd, "%u\t", bvalue->max_ttl);
	for(unsigned int i=0; i<10; i++) {
		fprintf(fd, "%u\t", fvalue->pkt_ttl_hist[i]);
	}
	for(unsigned int i=0; i<10; i++) {
		fprintf(fd, "%u\t", bvalue->pkt_ttl_hist[i]);
	}

	fprintf(fd, "%08x\t", fvalue->cumulative_flags);
	fprintf(fd, "%08x\t", bvalue->cumulative_flags);
	fprintf(fd, "%u\t", fvalue->retr_pkts);
	fprintf(fd, "%u\t", bvalue->retr_pkts);
	fprintf(fd, "%u\t", fvalue->retr_bytes);
	fprintf(fd, "%u\t", bvalue->retr_bytes);
	fprintf(fd, "%u\t", fvalue->ooo_pkts);
	fprintf(fd, "%u\t", bvalue->ooo_pkts);
	fprintf(fd, "%u\t", fvalue->ooo_bytes);
	fprintf(fd, "%u\t", bvalue->ooo_bytes);
	fprintf(fd, "%u\t", fvalue->min_win_bytes);
	fprintf(fd, "%u\t", bvalue->min_win_bytes);
	fprintf(fd, "%u\t", fvalue->max_win_bytes);
	fprintf(fd, "%u\t", bvalue->max_win_bytes);
	fprintf(fd, "%u\t", fvalue->mss);
	fprintf(fd, "%u\t", bvalue->mss);
	fprintf(fd, "%u\t", fvalue->wndw_scale);
	fprintf(fd, "%u\t", bvalue->wndw_scale);
	
	fprintf(fd, "\n");
}

static void flow_merge(const struct flow_id *key, const struct flow_info *value,
		const struct flow_id *key2, const struct flow_info *value2, 
		FILE *fd)
{
	/* For my convention, the forward direction is given by the first
	 * packet seen of the two flows.
	 * Mind that for unidirectional flows the forward flow is always
	 * the first one.
	 */
	if( value->first_seen < value2->first_seen ||
			value2->first_seen == 0)
		flow_print_full(key, value, key2, value2, fd);
	else
		flow_print_full(key2, value2, key, value, fd);
}

static int flow_scan(int fd, int op, struct flow_counters *cnt, FILE *out)
{
	struct flow_id key = { 0 }, key2, next_key;
	struct flow_info value = { 0 }, value2 = { 0 };
	unsigned int bidirectional = 0;
	unsigned int count = 0;
	
	/* Reset counters before starting the iteration. */
	*cnt = (struct flow_counters) { 0 };

	/* Browse the whole map and prints all relevant flow info. */
	while ( bpf_map_get_next_key(fd, &key, &next_key) == 0 ) {
		key = next_key;
		if ((bpf_map_lookup_elem(fd, &key, &value)) != 0) {
			fprintf(stderr,
				"ERR: bpf_map_lookup_elem failed key3:0x%p\n", &key);
			return -1; /* Maybe we could just go on with other keys... TODO */
		}
		printf("Chiara pompinara: %u\n", cnt->tot);
		cnt->tot++;

		switch (op) {
			case OP_PURGE:
				/* Lookup the other half of the flow, then dump if both
				 * are terminated.
				 */
				key_swap(&key, &key2);
				/* Must reset this struct to make simpler the management of 
				 * unidirectional flows (force flow_to_remove to return 
				 * > 0 in case the flow does not exist).
				 */
				value2 = (struct flow_info) { 0 };
				if ((bpf_map_lookup_elem(fd, &key2, &value2)) != 0) 
					/* No flow is present in the other direction. */
					bidirectional = 0;
				else 
			       		bidirectional = 1;
			
				/* TODO: what happens in case of unidirectional flows?
				 */
				if( ( flow_to_remove(&key, &value) > 0 ) && 
						( flow_to_remove(&key2, &value2) > 0 ) ) {
					bpf_map_delete_elem(fd, &key);
					cnt->purged++;
					if( bidirectional == 1 ) {
						cnt->tot++;
						bpf_map_delete_elem(fd, &key2); 
						cnt->purged++;
					}
					flow_merge(&key, &value, &key2, &value2, out);	
					cnt->dumped++;
				}
				else
					cnt->active++; /* The other flow will be counted later on. */

				count++;

				break;
			case OP_COUNT:
				count++;
				break;
			case OP_DUMP:
				flow_print(&key, &value, out);
				break;
		}


	}

	fflush(out);

   return count;
}

//static int flow_dump(int fd, char *filename)
//{
//	struct flow_id key = { 0 }, next_key;
//	struct flow_info value = { 0 };
//
//	/* Browse the whole map and prints all relevant flow info. */
//	while ( bpf_map_get_next_key(fd, &key, &next_key) == 0 ) {
//		if ((bpf_map_lookup_elem(fd, &next_key, &value)) != 0) {
//			fprintf(stderr,
//				"ERR: bpf_map_lookup_elem failed key:0x%p\n", &next_key);
//			return -1; /* Maybe we could just go on with other keys... TODO */
//		}
//
//		flow_print(&next_key, &value, stdout);
//		if ( flow_to_remove(&next_key, &value) )
//			bpf_map_delete_elem(fd, &next_key);
//
//
//		key = next_key;
//	}
//
//   return 0;
//}

void flow_poll2(int map_fd, int interval)
{
	struct flow_counters cnt;

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	/* Print stats "header" */
	if (verbose) {
		printf("\n");
	}

	while (1) {
		flow_scan(map_fd, OP_DUMP, &cnt, stdout);
		usleep(interval*MICROSEC_PER_SEC);
	}
}

void flow_poll(int map_fd, int interval, const char *out_path)
{
	//FILE *out=stdout;
	FILE *out = fopen("flows.txt","w");

	unsigned int active = 0;
	struct flow_counters cnt = { 0 };
	time_t timer;
    	char buffer[26];
    	struct tm* tm_info;


	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	/* Print stats "header" */
	if (verbose) {
		printf("\n");
	}

	while (1) {
    		timer = time(NULL);
    		tm_info = localtime(&timer);
    		strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);

		/* TODO: peridically change the filename/folder
		 * to organize the data into multiple files.
		 */
		active = flow_scan(map_fd, OP_PURGE, &cnt, out);
		printf("*******************************\n");
		printf("Timestamp: %s\n", buffer);
		printf("Active unidirectional flows: %d\n", active);
		printf("Tot flows: %u\n", cnt.tot);
		printf("Active flows: %u\n", cnt.active);
		printf("Purged flows: %u\n", cnt.purged);
		printf("Dumped flows: %u\n", cnt.dumped);
		usleep(interval*MICROSEC_PER_SEC);
	}
}

void flow_mon(int fd, int interval, char *outpath)
{
	while(1) {
		/* flow_dump(fd, filename); */
		printf("ok");
		exit(0);
		flow_poll2(fd,interval );
		flow_poll(fd, interval, outpath);
		usleep(interval*MICROSEC_PER_SEC);
	}
}
