#!/bin/bash

IFACE="eth2"
BPFPROG="tc_flowmon_kern.o"
BPFSEC="flowmon"
MAPFILENAME="tc_flowmon"

if [[ $# -ne 1 ]]
then
	echo "Wrong number of arguments!"
	exit -1
fi

if [ $1 == "start" ] 
then
	echo "Loading bpf program(s)...";
	clsact=`tc qdisc add dev $IFACE clsact`
	[[ ${#clsact} -eq 0 ]] &&  tc qdisc add dev $IFACE clsact;
	tc filter add dev $IFACE ingress bpf da obj $BPFPROG sec $BPFSEC
	id=`bpftool map show | tail -n 2 | head -n 1 | sed -e "s/\(^[0-9]*\):.*/\1/"`
	bpftool map pin id $id /sys/fs/bpf/tc/globals/${MAPFILENAME}_in
	tc filter add dev $IFACE egress bpf da obj $BPFPROG sec $BPFSEC
	id=`bpftool map show | tail -n 2 | head -n 1 | sed -e "s/\(^[0-9]*\):.*/\1/"`
	bpftool map pin id $id /sys/fs/bpf/tc/globals/${MAPFILENAME}_out
elif [ $1 == "stop" ]
	then
		echo "Unloading bpf program(s)...";
		rm -f /sys/fs/bpf/tc/globals/${MAPFILENAME}_in
		rm -f /sys/fs/bpf/tc/globals/${MAPFILENAME}_out
		tc filter del dev $IFACE ingress
		tc filter del dev $IFACE egress
	else
		echo "Unknown command!"
fi



