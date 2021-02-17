#!/bin/bash

IFACE="eth2"
BPFPROG="tc_flowmon_kern.o"
BPFSEC="flowmon"
BPFMAP="/sys/fs/bpf/tc/globals/flowmon_stats"

if [[ $# -ne 1 ]]
then
	echo "Wrong number of arguments!"
	exit -1
fi

cmd=$@
case $cmd in

	start)
		echo "Loading bpf program(s)...";
		clsact=`tc qdisc add dev $IFACE clsact`
		[[ ${#clsact} -eq 0 ]] &&  tc qdisc add dev $IFACE clsact;
		tc filter add dev $IFACE ingress bpf da obj $BPFPROG sec $BPFSEC
		tc filter add dev $IFACE egress bpf da obj $BPFPROG sec $BPFSEC
		;;

	stop)
		echo "Unloading bpf program(s)...";
		echo "Manually remove the pinned map when no more needed"
		;;

	purge)
		echo "Removing pinned map...";
		tc filter del dev $IFACE ingress
		tc filter del dev $IFACE egress
		rm -f $BPFMAP
		;;
	*)
		echo "Unknown command!"
esac



