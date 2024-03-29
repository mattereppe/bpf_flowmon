#!/bin/bash

# Load the necessary bpf programs to monitor
# network flows and run the userland utility
# to dump finished flows.

# Internal variables. Cannot be changed by external configuration
DEFAULTSFILE="/etc/default/bpfflowmon"
RUNDIR="/var/run/bpfflowmon/"
PIDFILE=$RUNDIR"$FLOWMON_NAME.pid"

# Default values, may be changed by setting the corresponding variables in 
# /etc/defaults/bpfflowmon or by providing them on the command line
# (the latter takes precedence).
FLOWMON_NAME="tc_flowmon_user"
UPLANED="/usr/local/bin/$FLOWMON_NAME"
IFACELIST=$RUNDIR"iface.list"
LOGFILE="/var/log/bpfflowmon.log"
DUMPDIR="/tmp"
IFACE="lo"
BPFPROG="/usr/local/lib/flowmon/tc_flowmon_kern.o"
BPFSEC="flowmon"
BPFMAP="/sys/fs/bpf/tc/globals/flowmon_stats"
DIR="both"
INTERVAL="10"
FORMAT="plaintext"

if [ -f "$DEFAULTSFILE" ]; then
	echo "reading from " $DEFAULTSFILE
	. $DEFAULTSFILE;
	else
	echo $DEFAULTSFILE;
fi

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
			[ -j | --json ] 
			[ --show-defaults ]
			[ -h | --help ]
			{ start | load | stop | unload | purge }
			
		Commands:
		start: load the filters on the specified devices and run the userland utility
		load: load the filters on the specified interfaces
		stop: stop the userland utility
		unload: stop the userland utility (if running) and remove bpf programs
		purge: remove bpf programs and purge the BPF map

		Options meaning:
		-i, --interface: network interface to load the inspection program (default: lo)
		-a, --all: load program on all interfaces
		--int: polling interval to dump flows
		-p, --program: name of the bpf program to load
		-s, --section: name of the bpf section to load
		-m, --map: name of the map to be used for saving flows statistics
		-d, --direction: load filter on the ingress/egress/both path (default: both)
		-w, --write: dump the flows on file 
		-u, --userland: name of the userland program to process flows
		-j, --json: format output as json
		--show-defaults: show defaults value for all parameters
		-h, --help: print this message and exit

		"
		exit 2
}

show_defaults()
{
	echo "Monitoring interface: " $IFACE
	echo "BPF program: " $BPFPROG
	echo "BPF program section name: " $BPFSEC
	echo "BPF map: " $BPFMAP
	echo "Userland program: " $UPLANED
	echo "Userland log file: " $LOGFILE
	echo "Queue direction: " $DIR
	echo "Dump directory: " $DUMPDIR
	echo "Dump interval: " $INTERVAL
	echo "Data format: " $FORMAT

	exit 3
}

load_bpf_programs()
{
		test -d $RUNDIR || mkdir $RUNDIR

		echo "Loading bpf program on: ";
		for i in $IFACE; do
			echo -n "- " $i ":"
			present=`tc qdisc show dev $i handle ffff: | grep -c "clsact"`;
			if [ $present -eq 0 ]; then
				echo -n " (Adding clsact)";
				tc qdisc add dev $i clsact;
			fi

			if [ "$DIR" == "ingress" ] || [ "$DIR" == "both" ]; then
				present=`tc filter show dev $i ingress | grep -c $BPFPROG`;
				if [ $present -gt 0 ]; then
					echo -n "	ingress already present/";
				else
					tc filter add dev $i ingress bpf da obj $BPFPROG sec $BPFSEC
				fi
			fi
			if [ "$DIR" == "egress" ] || [ "$DIR" == "both" ]; then
				present=`tc filter show dev $i egress | grep -c $BPFPROG`;
				if [ $present -gt 0 ]; then
					echo -n "egress already present ";
				else
					tc filter add dev $i egress bpf da obj $BPFPROG sec $BPFSEC
				fi
			fi

			echo "   done!"
		done
		echo "$IFACE" > $IFACELIST
}

stop_bpf_util()
{
	if [ -e $PIDFILE ]; then
		start-stop-daemon --stop --pidfile $PIDFILE
		rm -f $PIDFILE
	else
		echo "$UPLANED not running!"
	fi
}


remove_bpf_programs()
{
	if [ ! -f $IFACELIST ]; then
		echo "Unable to auto-detect interface list!";
		echo "Looking on all interfaces.";
		DEV_LIST=$(ip -o l show up | awk -F": " '{ print $2;}');
		IFACE="$DEV_LIST";
	else
		IFACE=`cat $IFACELIST`
	fi

	echo "Unloading bpf program(s)...";
	for i in $IFACE; do
		echo -n "- " $i ":"
		tc filter del dev $i ingress
		tc filter del dev $i egress
		echo "	 done!"
	done

	rm -f $IFACELIST
}

PARSED_ARGUMENTS=$(getopt -a -n $0 -o i:ap:s:m:d:w:u:jh --long all,interface:,int:,program:,section:,map:,direction:,write:,show-defaults,userland:,json,help -- "$@")
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
			BPFPROG="$2";
			test  -f $PROG  || ( echo "BPF program not found: $PROG"; exit 2;)
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
					  [ "$DIR" != "both" ]; then
				echo "Invalid filter direction: " $DIR;
				usage ;
			fi
			shift 2;;
		-w | --write)
			DUMPDIR="$2";
			shift 2;;
		--show-defaults)
			show_defaults;;
		-u | --userland)
			UPLANED="$2";
			test -x $UPLANED || echo "Userland utility not found or not executable: $UPLANED"; exit 2;
			;;
		-j | --json)
			FORMAT="json"
			shift
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
if [ "$FORMAT" == "json" ]; then
	FLOWMON_OPTS=$FLOWMON_OPTS" -j"
fi

#echo $FLOWMON_OPTS

case $CMD in

	load)
		load_bpf_programs;
		;;

	start)
		load_bpf_programs;

		echo "Starting..."
		 #start-stop-daemon --start -C -O $LOGFILE -b -m --pidfile $PIDFILE \
		start-stop-daemon --start -b -m --pidfile $PIDFILE \
		  	--startas $UPLANED  $FLOWMON_OPTS > cazzo.log 2>&1
		;;

	stop)
#		if [ -e $PIDFILE ]; then
#			start-stop-daemon --stop --pidfile $PIDFILE
#			rm -f $PIDFILE
#		else
#			echo "$UPLANED not running!"
#		fi
#
		stop_bpf_util;
		remove_bpf_programs;

		echo "Manually remove the pinned map when no more needed"
		;;

	unload)
		stop_bpf_util;
		remove_bpf_programs;
		;;
		
	purge)
		stop_bpf_util;
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
