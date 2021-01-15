# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
XDP_TARGETS := tc_flowmon_kern
USER_TARGETS := 
PYTHON_TARGETS := 

LLC ?= llc
CLANG ?= clang
CC := gcc

# Dependencies
USER_DEP := 

# Valid definition for all possible targets
XDP_C = ${XDP_TARGETS:=.c}
XDP_OBJ = ${XDP_C:.c=.o}
USER_C := ${USER_TARGETS:=.c}
USER_OBJ := ${USER_C:.c=.o} 

#LIBBPF_DIR = /home/debian/xdp-tutorial/libbpf/src/
LIBBPF_DIR = /usr/lib64/
#OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a
OBJECT_LIBBPF = libbpf.a

EXTRA_DEPS += 

#CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -g
#CFLAGS += -I/home/debian/headers/
#CFLAGS += -I/usr/include/x86_64-linux-gnu/
#LDFLAGS ?= -L$(LIBBPF_DIR)

#BPF_CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -I/home/debian/xdp-tutorial/headers/
#BPF_CFLAGS += -I/usr/include/x86_64-linux-gnu/ -D _DEBUG_
BPF_CFLAGS += -I/usr/include/x86_64-linux-gnu/ 
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

$(OBJECT_LIBBPF):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
	        echo "Error: Need libbpf submodule"; \
	        echo "May need to run git submodule update --init"; \
	        exit 1; \
	else \
	        cd $(LIBBPF_DIR) && $(MAKE) all; \
	        mkdir -p build; DESTDIR=build $(MAKE) install_headers; \
	fi

common_params.o: common_params.c common_params.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(USER_TARGETS): %: %.c  Makefile $(KERN_USER_H) $(EXTRA_DEPS) $(USER_OBJ) $(USER_DEP)
	$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o $@ \
         $< $(USER_DEP) $(LIBS) 

$(XDP_OBJ): %.o: %.c  Makefile $(KERN_USER_H) $(EXTRA_DEPS)
	$(CLANG) -S \
            -target bpf \
            -D __BPF_TRACING__ \
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
