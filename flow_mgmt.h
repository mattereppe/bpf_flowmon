#include "common.h"

#ifndef _FLOW_MGMG_H_
#define _FLOW_MGMG_H_

void flow_poll(int map_fd, int interval, const char * path);
void flow_poll2(int map_fd, int interval);
void flow_merge(int map_fd_in, int map_fd_out, int interval);

#endif
