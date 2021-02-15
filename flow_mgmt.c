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
#include <arpa/inet.h>

#include "common.h"

#define PINFILENAMELEN 40
extern int verbose;

#define MICROSEC_PER_SEC 1000000 /* 10^6 */
#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
#define FLOW_INACTIVE_TIMEOUT_SEC 30

/* Flow termination reasons:
 * 	1 - Flow terminated normally (connection closed).
 * 	2 - Flow terminated abnormally (connection reset).
 * 	3 - Timeout expired.
 */
#define FLOW_NOTERM 0
#define FLOW_TERM_CLOSED 1
#define FLOW_TERM_RESET 2
#define FLOW_TERM_TIMEOUT 3

/* Check whether the flow has to be removed,
 * but does not actually remove it.
 * Return values:
 * < 0: Error while checking the conditions.
 * > 0: Flow should be removed because expired.
 * 	(see reasons in the specific macros).
 * = 0: Flow should not be removed (still active).
 */
static int flow_to_remove(struct flow_id *key, struct flow_info *value)
{
	int err;
	unsigned long int last;

	/* Remove terminated or expired flows. */
	struct timespec now;

	/* TODO: Remove TCP flows according to status flags. */
	
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

/* Print the flow statistics.
 * TODO: This function should be replaced with a more appropriate 
 * output method.
 */
static int flow_print(struct flow_id *key, struct flow_info *value)
{
	char ip_addr[INET_ADDRSTRLEN];

	/* Print the flow id. */
	if( inet_ntop(AF_INET, (const void *)(&(key->saddr)), ip_addr, INET_ADDRSTRLEN) != 0 )
		printf("%s:%d",ip_addr, key->sport);
	printf(" -> ");
	if( inet_ntop(AF_INET, (const void *)(&(key->daddr)), ip_addr, INET_ADDRSTRLEN) != 0 )
		printf("%s:%d",ip_addr, key->dport);
	printf(" %d ",key->proto);

	/* Print statistics. */
	printf("\t%d\t%d\t%lld\t%lld\n", value->pkts, value->bytes, value->first_seen, value->last_seen);
	
	return 0;
}

static int flow_scan(int fd)
{
	struct flow_id key = { 0 }, next_key;
	struct flow_info value = { 0 };

	/* Browse the whole map and prints all relevant flow info. */
	while ( bpf_map_get_next_key(fd, &key, &next_key) == 0 ) {
		if ((bpf_map_lookup_elem(fd, &next_key, &value)) != 0) {
			fprintf(stderr,
				"ERR: bpf_map_lookup_elem failed key:0x%p\n", &next_key);
			return -1; /* Maybe we could just go on with other keys... TODO */
		}

		flow_print(&next_key, &value);
		if ( flow_to_remove(&next_key, &value) )
			bpf_map_delete_elem(fd, &next_key);


		key = next_key;
	}

   return 0;
}

static int flow_dump(int fd, char *filename)
{
	struct flow_id key = { 0 }, next_key;
	struct flow_info value = { 0 };

	/* Browse the whole map and prints all relevant flow info. */
	while ( bpf_map_get_next_key(fd, &key, &next_key) == 0 ) {
		if ((bpf_map_lookup_elem(fd, &next_key, &value)) != 0) {
			fprintf(stderr,
				"ERR: bpf_map_lookup_elem failed key:0x%p\n", &next_key);
			return -1; /* Maybe we could just go on with other keys... TODO */
		}

		flow_print(&next_key, &value);
		if ( flow_to_remove(&next_key, &value) )
			bpf_map_delete_elem(fd, &next_key);


		key = next_key;
	}

   return 0;
}

void flow_poll(int map_fd, int interval)
{
	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	/* Print stats "header" */
	if (verbose) {
		printf("\n");
	}

	while (1) {
		flow_scan(map_fd);
		usleep(interval*MICROSEC_PER_SEC);
	}
}

void flow_merge(int map_fd, int map_fd_out, int interval)
{
	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	/* Print stats "header" */
	if (verbose) {
		printf("\n");
	}

	while (1) {
		flow_scan(map_fd);
		usleep(interval*MICROSEC_PER_SEC);
	}
}

void flow_mon(int fd, int interval, char *filename)
{
	while(1) {
		flow_dump(fd, filename);
		usleep(interval*MICROSEC_PER_SEC);
	}
}
