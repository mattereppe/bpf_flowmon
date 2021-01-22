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

static const char *default_filename = "/sys/fs/bpf/tc/globals/tc_flowmon";
int verbose = 1;

#define MICROSEC_PER_SEC 1000000 /* 10^6 */

static int flow_print(struct flow_id *key, struct flow_info *value)
{
	char ip_addr[INET_ADDRSTRLEN];

	if( inet_ntop(AF_INET, (const void *)(&(key->saddr)), ip_addr, INET_ADDRSTRLEN) != 0 )
		printf("%s:%d",ip_addr, key->sport);
	printf(" -> ");
	if( inet_ntop(AF_INET, (const void *)(&(key->daddr)), ip_addr, INET_ADDRSTRLEN) != 0 )
		printf("%s:%d",ip_addr, key->dport);
	printf(" %d ",key->proto);
	printf("\t%d\t%d\n", value->pkts, value->bytes);
	
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

		key = next_key;
	}

   return 0;
}

static void flow_poll(int map_fd, int interval)
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

static int __check_map_fd_info(int map_fd, struct bpf_map_info *info,
			       struct bpf_map_info *exp)
{
	__u32 info_len = sizeof(*info);
	int err;

	if (map_fd < 0)
		return EXIT_FAIL;

        /* BPF-info via bpf-syscall */
	err = bpf_obj_get_info_by_fd(map_fd, info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: %s() can't get info - %s\n",
			__func__,  strerror(errno));
		return EXIT_FAIL_BPF;
	}

	if (exp->key_size && exp->key_size != info->key_size) {
		fprintf(stderr, "ERR: %s() "
			"Map key size(%d) mismatch expected size(%d)\n",
			__func__, info->key_size, exp->key_size);
		return EXIT_FAIL;
	}
	if (exp->value_size && exp->value_size != info->value_size) {
		fprintf(stderr, "ERR: %s() "
			"Map value size(%d) mismatch expected size(%d)\n",
			__func__, info->value_size, exp->value_size);
		return EXIT_FAIL;
	}
	if (exp->max_entries && exp->max_entries != info->max_entries) {
		fprintf(stderr, "ERR: %s() "
			"Map max_entries(%d) mismatch expected size(%d)\n",
			__func__, info->max_entries, exp->max_entries);
		return EXIT_FAIL;
	}
	if (exp->type && exp->type  != info->type) {
		fprintf(stderr, "ERR: %s() "
			"Map type(%d) mismatch expected type(%d)\n",
			__func__, info->type, exp->type);
		return EXIT_FAIL;
	}

	return 0;
}

int check_map_fd(int map_fd)
{
   struct bpf_map_info map_expect = { 0 };
   struct bpf_map_info info = { 0 };

	map_expect.key_size = sizeof(struct flow_id);
	map_expect.value_size = sizeof(struct flow_info);
	map_expect.max_entries = MAXFLOWS;
	
	return __check_map_fd_info(map_fd, &info, &map_expect);
};

void usage(const char *prog_name)
{
	printf("Usage: %s [options]\n", prog_name);

	printf("\nwhere options can be:\n");
	printf("-f <filename>: pinned filename for the map\n");
	printf("-i <interval>: reporting period in sec [default=1s; 0=print once and exit]\n");
	printf("q|v: quiet/verbose mode [default to: verbose]\n");
}

int main(int argc, char **argv)
{
	const char *pinned_file = NULL;
	int interval = 1;
	int map_fd = -1;
	int ret, opt;

	while ((opt = getopt(argc, argv, "f:i:qv") ) != -1 )
	{
		switch (opt) {
			case 'f':
				pinned_file = optarg;
				break;
			case 'i':
				interval = atoi(optarg);
				break;
			case 'v': 
				verbose = true;
				break;
			case 'q':
				verbose = false;
				break;
			default:
				usage(argv[0]);
				goto out;
		}
	}

	if( !pinned_file )
		pinned_file = default_filename;

	if( !pinned_file || interval < 0 )
	{
		usage(argv[0]);
		goto out;
	}

	map_fd = bpf_obj_get(pinned_file);
	if( map_fd < 0 ) {
		fprintf(stderr, "bpf_obj_get(%s): %s[%d]\n",
				pinned_file, strerror(errno), errno);
		goto out;
	}

	if( (ret = check_map_fd(map_fd)) < 0 ) {
		fprintf(stderr, "Map descriptor not compliant with what expected!\n");
		goto out;
	}

	flow_poll(map_fd, interval);
	ret = 0;

out:
	if( map_fd != -1 )
		close(map_fd);

	return ret;
}
