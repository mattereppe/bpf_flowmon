#!/bin/bash

# Load the necessary bpf programs to monitor
# network flows and run the userland utility
# to dump finished flows.

FLOWMON_NAME="tc_flowmon_user"
UPLANED="/usr/local/bin/$FLOWMON_NAME"
PIDFILE="/var/run/bpfflowmon/$FLOWMON_NAME.pid"
IFACELIST="/var/run/bpfflowmon/iface.list"
LOGFILE="/var/log/bpfflowmon.log"
DUMPDIR="/tmp"

IFACE="lo"
BPFPROG="tc_flowmon_kern.o"
BPFSEC="flowmon"
BPFMAP="/sys/fs/bpf/tc/globals/flowmon_stats"
DIR="ingress"
OUTDIR="./"
INTERVAL="10"

usage()
{
	echo "Usage: $0 [ -i | --interface ] <device>
			[ -a | --all ]
			[ --int ] <polling_interval>
			[ -p | --program ] <prog_name>
			[ -s | --section ] <sec_name>
			[ -m | --map ] <map_name>
			[ -d | --dir ] [ingress | egress | all]
			[ -w | --write ] <directory>
			[ -u | --userland ] <user_prog>
			[ --show-defaults ]
			[ -h | --help ]
			{ start | stop | purge }
			
		Commands:
		start: load the filters on the specified devices and run the userland utility
		stop: stop the userland utility
		purge: stop the userland utility (if running) and remove bpf programs

		Options meaning:
		-i, --interface: network interface to load the inspection program (default: lo)
		-a, --all: load program on all interfaces
		--int: polling interval to dump flows
		-p, --program: name of the bpf program to load
		-s, --section: name of the bpf section to load
		-m, --map: name of the map to be used for saving flows statistics
		-d, --direction: load filter on the ingress/egress/both path (default: ingress)
		-w, --write: dump the flows on file (default: stdout)
		-u, --userland: name of the userland program to process flows
		--show-defaults: show defaults value for all parameters
		-h, --help: print this message and exit

		"
		exit 2
}

show_defaults()
{
	echo "Monitoring interface: " $IFACE
	echo "BPF program: " $BPFPROG
	echo "BPF map: " $BPFMAP
	echo "Queue direction: " $DIR
	echo "Dump directory: " $OUTDIR
	echo "Dump interval: " $INTERVAL
	echo "Userland program: " $UPLANED

	exit 3
}

remove_bpf_programs()
{
	if [ ! -f $IFACELIST ]; then
		echo "Unable to auto-detect interface list!";
		exit 1;
	fi
	IFACE=`cat $IFACELIST`

	echo "Unloading bpf program(s)...";
	for i in $IFACE; do
		echo -n "- " $i ":"
		tc filter del dev $i ingress
		tc filter del dev $i egress
		echo "	 done!"
	done
}

PARSED_ARGUMENTS=$(getopt -a -n $0 -o i:ap:s:m:d:w:h --long all,interface:,program:,section:,map:,dir:,write:,show-defaults,help -- "$@")
VALID_ARGUMENTS=$?
if [ "$VALID_ARGUMENTS" != "0" ]; then
	usage
fi

#echo "PARSED_ARGUMENTS is $PARSED_ARGUMENTS"
eval set -- "$PARSED_ARGUMENTS"
while :
do
	case "$1" in
		-a | --all)
			IFACE=all;
			shift ;;
		-i | --interface)
			IFACE="$2";
			shift 2;;
		--int)
			INTERVAL="$2";
			shift 2;;
		-p | --program)
			PROG="$2";
			shift 2;;
		-s | --section)
			SEC="$2";
			shift 2;;
		-m | --map)
			MAP="$2"
			shift 2;;
		-d | --direction)
			DIR="$2";
			if [ "$DIR" != "ingress" ] &&
					  [ "$DIR" != "egress" ] &&
					  [ "$DIR" != "all" ]; then
				echo "Invalid filter direction: " $DIR;
				usage ;
			fi
			shift 2;;
		-w | --write)
			OUTDIR="$2";
			shift 2;;
		--show-defaults)
			show_defaults;;
		-u | --userland)
			UPLANED="$2";
			;;
		-h | --help)
			usage;;
 # -- means the end of the arguments; drop this, and break out of the while loop
		--) 
			shift; 
			break ;;
		*) echo "Unexpected option: $1 - this should not happen."
			usage ;;
 	esac
done

if [ "$IFACE" == all ]; then
	DEV_LIST=$(ip -o l show up | awk -F": " '{ print $2;}');
	IFACE="$DEV_LIST";
fi

if [[ $# -ne 1 ]]
then
	echo "Wrong number of arguments!"
	exit -1
fi

CMD=$@

FLOWMON_OPTS="-- -i $INTERVAL -d $DUMPDIR -l $LOGFILE"

case $CMD in

	start)
		echo "Loading bpf program on: ";
		for i in $IFACE; do
			echo -n "- " $i ":"
			clsact=`tc qdisc add dev $i clsact`
			[[ ${#clsact} -eq 0 ]] &&  tc qdisc add dev $i clsact;

			if [ "$DIR" == "ingress" ] || [ "$DIR" == "all" ]; then
				tc filter add dev $i ingress bpf da obj $BPFPROG sec $BPFSEC
			fi
			if [ "$DIR" == "egress" ] || [ "$DIR" == "all" ]; then
				tc filter add dev $i egress bpf da obj $BPFPROG sec $BPFSEC
			fi

			echo "   done!"
		done
		echo "$IFACE" > $IFACELIST

		# start-stop-daemon --start -C -O $LOGFILE -b -m --pidfile $PIDFILE \
		start-stop-daemon --start -b -m --pidfile $PIDFILE \
		  	--startas $UPLANED  $FLOWMON_OPTS
		;;

	stop)
		start-stop-daemon --stop --pidfile $PIDFILE

		remove_bpf_programs;

		echo "Manually remove the pinned map when no more needed"
		;;

	purge)
		remove_bpf_programs;
		
		echo -n "Removing pinned map...";
		rm -f $BPFMAP
		echo "	done!";

		;;
	*)
		echo "Unknown command: " $CMD;
		usage;
		exit 1
esac

exit 0
