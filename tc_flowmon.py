#!/usr/bin/python3
# 
# flowlabel BPF programs to analyse flow label 
#           statistics in IPv6 header. Conceived
#           to detect steganographic channels.
#
# Copyright (C) 2020 Matteo Repetto.
# Licensed under the GNU Public License v2.0.
#

from bcc import BPF
from pyroute2 import IPRoute
from pyroute2.netlink.exceptions import NetlinkError
import time
import sys
import subprocess
import argparse
import pathlib
import inspect
import json
import netifaces

class InvalidParameterError(Exception):
    """Exception raised for invalid parameters in the input

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message

def getAttrs(unknownClass):
    attr_list = list()
    # getmembers() returns all the
    # members of an object
    for i in inspect.getmembers(unknownClass):
        # i[0] contains the name
        # i[1] contains the value
    
        # to remove private and protected
        # functions
        if not i[0].startswith('_'):
    
            # To remove other methods that
            # doesnot start with a underscore
            if not inspect.ismethod(i[1]):
                attr_list.append(i)

    return attr_list

def toJson(bpfMap):
    fieldList = list()

    num = len(values)
    items = list()
    for i in range(0,num):

        # TODO: Manage multiple different BPF map types
        # This works for BPF_HASH (and may BPF_ARRAY)
        key = getAttrs(bpfMap[i][0])
        value = getAttrs(bpfMap[i][1])
        item = dict()
        item["key"] = dict(getAttrs(bpfMap[i][0]))
        item["value"] = dict(getAttrs(bpfMap[i][1]))
        items.append(item)
    
    # TODO: Add other descriptive fields, if necessary
    metrics = dict()
    metrics["metrics"] = items
    # TODO: Add support for serialization of uncommon c_types (e.g., arrays of int)
    print(json.dumps( metrics ))


# Parse parameters from the command line
parser = argparse.ArgumentParser(description='Start bpf flow monitor.',
		epilog='Mind that these are unidirectional flows that must be aggregated and purged!!')
parser.add_argument('-i','--interface', default='all',
		help='Network interface to attach the program to', required=False)
parser.add_argument('--int', default=5, type=int, 
		help='Polling interval of the bpf program', metavar='INT')
parser.add_argument('-w','--write',default='stdout', 
		help='Output of the program (default: stdout)',metavar='FILE')
parser.add_argument('-p','--program',default='tc_flowmon_kern.c', 
		help='Bpf program to run (default: tc_flowmon_kern.c)',metavar='FILE')
parser.add_argument('-s','--section', default='flow_mon',
		help='Section of the bpf program to run', required=False)
parser.add_argument('-m','--map',default='flowmon_stats', 
		help='Map file name (default: flowmon_stats)',metavar='FILE')
parser.add_argument('-d','--direction', help='Direction to apply the filter (default: egress)', default='ingress', 
		choices=['ingress','egress','all'])
param = parser.parse_args()


dev=param.interface
output_interval=param.int
output_file_name=param.write
bpfprog=param.program
bpfsec=param.section
bpfmap=param.map
direction=param.direction


ipr = IPRoute()

if dev == 'all':
    if_list=netifaces.interface()
else:
    if_list = []
    if_list.append(dev)

prog = BPF(src_file=bpfprog, cflags=["-I/usr/include/", "-D_DEBUG_=1", "-D __BPF_TRACING__"], debug=0)
fn = prog.load_func(bpfsec, BPF.SCHED_CLS)

for iface in if_list:
    idx = ipr.link_lookup(ifname=iface)[0]
    try:
        ipr.tc("add", "clsact", idx, "ffff:")
    except NetlinkError as err:
        if err.code == 17:
            print("Skipping creation of clsact qdisc on " + iface)

    if direction == "ingress" or direction == "all":
        ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, 
                parent="ffff:fff2", classid=1, direct_action=True)

    if direction == "egress" or direction == "all":
        ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, 
                parent="ffff:fff3", classid=1, direct_action=True)
        
hist = prog.get_table(bpfmap)

try:
    prev = time.time()
    if output_file_name != "stdout":
        orig_stdout = sys.stdout
        output_file = open(output_file_name,'w')
        sys.stdout = output_file
    while True:
        time.sleep(output_interval) # Wait for next values to be available
        values = hist.items()

        now = time.time()
        # -- TODO: Put the following in a function 
            #print(toJson(values[i][0]))
        toJson(values)

        print(values);


#            period = now - prev
#            packets = int((hist_values[i][1]).value) - int((prev_values[i][1]).value)
#            #print("{0:05x}".format(i),"\t\t", packets, "\t\t", (hist_values[i][1]).value, "\t[",period, "s]")
#            current, peak = tracemalloc.get_traced_memory()
#            print("After printing");
#            print(f"Current memory usage is {current / 10**6}MB; Peak was {peak / 10**6}MB");
#        # -- End function
#        print('\n')
except KeyboardInterrupt:
    sys.stdout.close()
    pass
finally:
    try:
        sys.stdout = orig_stdout
        output_file.close()
    except NameError:
        # Do nothing
        no_op = 0


#subprocess.run("./tc_fl_user")

for iface in if_list:
    idx = ipr.link_lookup(ifname=iface)[0]
    try:
        ipr.tc("del", "clsact", idx, "ffff:")
    except NetlinkError as err:
        if err.code == 22:
            print("Unable to remove clsact qdisc on " + iface)

