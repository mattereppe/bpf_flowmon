#include "common.h"

#ifndef __TO_JSON_H__
#define __TO_JSON_H__
char * to_json(const struct flow_id *fkey, const struct flow_info *fvalue,
		const struct flow_id *bkey, const struct flow_info *bvalue);
#endif
