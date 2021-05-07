# bpfFlowMon

Network flow monitoring with bpf programs. This is part of the investigation on how bpf filters can be used for packet inspection. It is not conceived as fully replacement of existing tools, which use more efficient techniques based on kernel by-pass or hardware support. Instead, the main objective is to understand if and to what extend BPF programs can be used in softwarized environments, where existing techniques do not bring the expected benefits or are not applicable.
The current version is far from being complete and only represents the preliminary step towards a more flexible approach based on the creation of dynamic programs for different tasks. The ultimate goals would be to replace existing scripting techniques already available for IDS and other cybersecurity tools with BPF programs.

## Scope and limitations

The current implementation provides a static set of information about network and transport layers. Ethernet frames are not counted to provide a more general tool that works on several links (including VPNs and tunnels).
Both IPv4 and IPv6 are supported. Only a very limited number of TCP features are collected. This is due to limitations of the BPF framework, which imposes a limited stack size and execution branches. Future work would consider the possibility to use tail calls or multiple filters to overcome these limitations.
Though the current set of feature is only a subset of what envisioned by protocols like NetFlow and IPFIX (see, for example, the list of <A href="https://www.ntop.org/guides/nprobe/flow_information_elements.html">Information Elemenents available from nProbe</A>), the code is quite limited in size, and allows extensions to collect custom metrics and statistics. Once more, we remark that the current implementation is rather limited by the stack size and runtime verification.
Flows are identified by the common pattern <code><src_ip_addr, dst_ip_addr, proto, src_port, dst_port></code>. Termination is detect by FIN/RST flags for TCP flows, and by an inactivity timeout in any case. Termination of other connection oriented protocols (like SCTP) is not implemented yet. ICMP flows also report the specific operation (inferred from the <code>type</code> field), which is reported in the <code>src_port</code> field.

So far, the <code>TC</code> hook is used, because it allows to inspect both incoming and outgoing traffic. Both a single or all interfaces can be monitored, to support different use cases. Porting to the XDP hook is rather straighforward, but in that case outgoing traffic is not visible. This means that routed connections could be seen entirely (by monitoring all interfaces), whereas only half of the local connections is visible (received packets).

The main objective so far was to investigate the possibility to collect metrics and statistics through BPF programs, and less effort has been devoted to make the whole framework user-friendly. The BPF code currently supports both <A href="https://github.com/libbpf/libbpf">libbpf</A> and <A href="https://github.com/iovisor/bcc">BCC</A>, but the userland utility has been developed only for the former, and only partially. For all of these reason, management of BPF programs is done through a dedicated script instead of being integrated into the userland utility.

Monitoring of a subset of interfaces is not supported by the current management script. The extension is rather simple, but this use case looks less interesting than monitoring a single interface or all of them. 


## Build and run

This repository provides three main tools:
* A BPF program for the <code>TC</code> hook, which collects metrics and statistics for unidirectional network flows (<code>tc_flowmon_kern.o</code>).
* A userland utility that scans the list of flows, merges bidirectional flows, dumps and purges terminated flows (<code>tc_flowmon_user</code>).
* A management script used to load/unload BPF programs and run the userland utility (<code>tc_flowmon.sh</code>).

To compile the code, just run:
```
make 
```
and
```
make install
```
to install the userland utility to <code>/usr/local/bin</code>.

To use the framework, you can either load the BPF programs through the management script and then run the userland utility manually, or launch everyting as a daemon through the management script.

For the first option, use the <code>load</code> command of the script:
```
% sudo ./tc_flowmon.sh -a load
```
and then start the userland utility:
```
% sudo ./tc_flowmon_user -i 10 
```
To stop the utility, use <code>Cnt-C</code>. To unload the BPF programs:
```
% sudo ./tc_flowmon.sh unload
```

For running the utility as a daemon, just start it through the management script (this will also load the BPF programs):
```
% sudo ./tc_flowmon.sh -i eth2 start
```
and when done stop it:
```
% sudo ./tc_flowmon.sh stop
```

Note that you have to explicitely remove the BPF map. This can be done with the <code>purge</code> command:
```
% sudo ./tc_flowmon.sh purge
```

## Usage

There are several paramters that can be given to the userland utility. They are reported by the <code>--help</code> option:
```
% ./tc_flowmon_user  --help
./tc_flowmon_user: invalid option -- '-'
Usage: ./tc_flowmon_user [options]

where options can be:
-f <filename>: pinned filename for the map (full path)
-p <filename>: pinned filename for the map (use default path)
-i <interval>: reporting period in sec [default=1s; 0=print once and exit]
-d <dir>: directory where to save dumped flows (default to current dir)
-l <file>: log messages to file (default: stdout)
q|v: quiet/verbose mode [default to: verbose]
```
These options can also be passed through the management script, which also includes additional parameters for loading BPF programs:
```
% ./tc_flowmon.sh --help
Usage: ./tc_flowmon.sh [ -i | --interface ] <device>
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
		-w, --write: dump the flows on file (default: stdout)
		-u, --userland: name of the userland program to process flows
		--show-defaults: show defaults value for all parameters
		-h, --help: print this message and exit

```
Default values in this case can be read directly from the script of listed with the <code>--show-defaults</code> option.

## Testing

The easiest way to test the program is to inject some traffic from pcap traces. The <A href="https://tcpreplay.appneta.com/">tcpreplay</A> utility can be used to this purpose, together with the <A href="https://tcpreplay.appneta.com/wiki/captures.html">sample captures</A>.

## Acknowledgement

This work was supported in part by the European Commission under Grant Agreements no. 786922 (<A href="https://www.astrid-project.eu/">ASTRID</A>) and no. 833456 (<A href="https://guard-project.eu/">GUARD</A>).





