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
#include "flow_mgmt.h"

#define PINFILENAMELEN 40
static const char *default_map_filename = "/sys/fs/bpf/tc/globals/flowmon_stats";
static const char *default_map_path = "/sys/fs/bpf/tc/globals/";
int verbose = 1;

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
	fprintf(stderr,"Usage: %s [options]\n", prog_name);

	fprintf(stderr,"\nwhere options can be:\n");
	fprintf(stderr,"-f <filename>: pinned filename for the map (full path)\n");
	fprintf(stderr,"-p <filename>: pinned filename for the map (use default path)\n");
	fprintf(stderr,"-i <interval>: reporting period in sec [default=1s; 0=print once and exit]\n");
	fprintf(stderr,"-d <dir>: directory where to save dumped flows (default to current dir)\n");
	fprintf(stderr,"-l <file>: log messages to file (default: stdout)\n");
	fprintf(stderr,"q|v: quiet/verbose mode [default to: verbose]\n");
}

int main(int argc, char **argv)
{
	const char *map_filename = NULL;
	const char *out_path = NULL;
	const char *logfile = NULL;
	char pinned_file[PINFILENAMELEN];
	int interval = 1;
	int map_fd = -1;
	int ret, opt;

	while ((opt = getopt(argc, argv, "f:p:i:d:l:qv") ) != -1 )
	{
		switch (opt) {
			case 'f':
				map_filename = optarg;
				break;
			case 'p':
				if( (strlen(default_map_path) + 1) > PINFILENAMELEN )
				{
					fprintf(stderr, "Internal path for pinning the map too long!\n");
					fprintf(stderr, "This is very strange, and shouldn't happen.\n");
					exit(-1);
				}
				strcpy(pinned_file, default_map_path);
				if( (strlen(pinned_file) + strlen(optarg) + 1) 
						> PINFILENAMELEN )
				{
					fprintf(stderr, "Filename for pinning the map too long!\n");
					exit(-1);
				}
				strcat(pinned_file, optarg);
				map_filename = pinned_file;
				break;
			case 'i':
				interval = atoi(optarg);
				break;
			case 'd':
				out_path = optarg;
				break;
			case 'v': 
				verbose = true;
				break;
			case 'q':
				verbose = false;
				break;
			case 'l':
				logfile = optarg;
				break;
			default:
				usage(argv[0]);
				goto out;
		}
	}

	if( !map_filename )
		map_filename = default_map_filename;

	if( !map_filename || interval < 0 )
	{
		usage(argv[0]);
		goto out;
	}

	map_fd = bpf_obj_get(map_filename);
	if( map_fd < 0 ) {
		fprintf(stderr, "bpf_obj_get(%s): %s[%d]\n",
				map_filename, strerror(errno), errno);
		goto out;
	}

	if( (ret = check_map_fd(map_fd)) < 0 ) {
		fprintf(stderr, "Map descriptor not compliant with what expected!\n");
		goto out;
	}

	flow_poll(map_fd, interval, logfile, out_path);
	
	ret = 0;

out:
	if( map_fd != -1 )
		close(map_fd);

	return ret;
}
