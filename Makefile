 # SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
XDP_TARGETS := tc_flowmon_kern
USER_TARGETS := tc_flowmon_user
PYTHON_TARGETS := 

LLC ?= llc
CLANG ?= clang
CC := gcc

# Dependencies
USER_DEP := *.h
COMMON_H := common.h

# Valid definition for all possible targets
XDP_C = ${XDP_TARGETS:=.c}
XDP_OBJ = ${XDP_C:.c=.o}
USER_C := ${USER_TARGETS:=.c} flow_mgmt.c
USER_OBJ := ${USER_C:.c=.o} 

#LIBBPF_DIR = /home/debian/xdp-tutorial/libbpf/src/
LIBBPF_DIR = /usr/lib64/
#OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a
OBJECT_LIBBPF = libbpf.a

EXTRA_DEPS += *.h

#CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -g
#CFLAGS += -I/home/debian/headers/
#CFLAGS += -I/usr/include/x86_64-linux-gnu/
#LDFLAGS ?= -L$(LIBBPF_DIR)
CFLAGS += -D __FLOW_IPV4__

#BPF_CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -I/home/debian/xdp-tutorial/headers/
BPF_CFLAGS += -I/usr/include/x86_64-linux-gnu/ -D _DEBUG_ -D __BPF_TRACING__ -D __FLOW_IPV4__  -D __FLOW_IPV6__
#BPF_CFLAGS += -I/usr/include/x86_64-linux-gnu/ 
# LIBBPF headers are installed in /usr/include/bpf

# -l: says to use the excat name (do not prepend "lib" and do to select between ".a" or ".so")
LIBS = -l:libbpf.a -lelf -lz $(USER_LIBS)

all: llvm-check $(USER_TARGETS) $(XDP_OBJ) 

.PHONY: clean $(CLANG) $(LLC)


clean:
	rm -rf $(LIBBPF_DIR)/build
	rm -f $(USER_TARGETS) $(XDP_OBJ) $(USER_OBJ) $(PYTHON_TARGETS)
	rm -f *.ll
	rm -f *~

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
	        if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
	                echo "*** ERROR: Cannot find tool $${TOOL}" ;\
	                exit 1; \
	        else true; fi; \
	done

$(USER_TARGETS): %: %.c  Makefile $(COMMON_H) $(EXTRA_DEPS) $(USER_OBJ) $(USER_DEP)
	$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o $@ \
         $(USER_OBJ) $(LIBS) 

$(XDP_OBJ): %.o: %.c  Makefile $(COMMON_H) $(EXTRA_DEPS)
	$(CLANG) -S \
            -target bpf \
            $(BPF_CFLAGS) \
            -Wall \
            -Wno-unused-value \
            -Wno-pointer-sign \
            -Wno-compare-distinct-pointer-types \
            -Werror \
            -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

$(PYTHON_TARGETS): template.py template.c
	sed -e '/BPFPROG_SRC_CODE/ {' -e 'r template.c' -e 'd' -e '}' template.py > $@
	chmod a+x $@
