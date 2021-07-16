/* Very simple and preliminary implementation
 * for exporting to json. Needs to be 
 * re-written after a more structured userland
 * application is implemented.
 */
#include "common.h"
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define JSONBUFSIZE 4096

char jsonbuf[JSONBUFSIZE];
int counter = 0;

char *jsonheader()
{
	return("{");
}

char *jsontrailer()
{
	return("}");
}

int check(const char *tmp, const char *jsonbuf) 
{
		return 0;
}

int append_to_json(char *json, const char *tmp)
{
	int len = strlen(jsonbuf);
	if( strlen(tmp) + len + 1 < JSONBUFSIZE ) {
		if( jsonbuf[len-1] != '{' &&
				tmp[0] != '}')
			strcat(jsonbuf,",");
		strcat(jsonbuf,tmp);
		return 0;
	}
	else
		return 1;
}

/* fkey is expected to be the forward direction, by convention the 
 * peer that was seen first.
 */
char * to_json(const struct flow_id *fkey, const struct flow_info *fvalue,
		const struct flow_id *bkey, const struct flow_info *bvalue)
{
	char tmp[JSONBUFSIZE];
	char ip_saddr[INET6_ADDRSTRLEN], ip_daddr[INET6_ADDRSTRLEN];
	char *ip_slabel, *ip_dlabel;
	int family;

	bzero(jsonbuf, JSONBUFSIZE);
	strcat(jsonbuf, jsonheader());

	sprintf(tmp,"\"FLOW_ID\": \"%d\"", counter);
	append_to_json(jsonbuf, tmp);

	sprintf(tmp,"\"IP_PROTOCOL_VERSION\": \"%d\"", fvalue->version);
	append_to_json(jsonbuf, tmp);
	
	
	if( fvalue->version == 4 ) {
		family=AF_INET;
		ip_slabel="IPV4_SRC_ADDR";
		ip_dlabel="IPV4_DST_ADDR";
	}
	else {
		family=AF_INET6;
		ip_slabel="IPV6_SRC_ADDR";
		ip_dlabel="IPV6_DST_ADDR";
	}
	if( inet_ntop(family, (const void *)(&(fkey->saddr)), ip_saddr, INET6_ADDRSTRLEN) == 0 )
		strcpy(ip_saddr,"ERROR");
	if( inet_ntop(family, (const void *)(&(fkey->daddr)), ip_daddr, INET6_ADDRSTRLEN) == 0 )
		strcpy(ip_daddr,"ERROR");

	sprintf(tmp,"\"%s\": \"%s\", \"%s\": \"%s\"", ip_slabel, ip_saddr, ip_dlabel, ip_daddr);
	append_to_json(jsonbuf, tmp);
	
	sprintf(tmp,"\"PROTOCOL\": \"%d\"", fkey->proto);
	append_to_json(jsonbuf, tmp);
	sprintf(tmp,"\"L4_DST_PORT\": \"%d\", \"L4_SRC_PORT\": \"%d\"", fkey->dport, fkey->sport);
	append_to_json(jsonbuf, tmp);

	long long int last_seen = 0;
	if( fvalue->last_seen > bvalue->last_seen )
		last_seen=fvalue->last_seen;
	else
		last_seen=bvalue->last_seen;
	sprintf(tmp,
			"\"FLOW_START_MICROSECONDS\": \"%lld\",\"FLOW_END_MICROSECONDS\": \"%lld\", \"FLOW_DURATION_MICROSECONDS\": \"%lld\"", 
			fvalue->first_seen/1000, last_seen/1000,
			(last_seen-fvalue->first_seen)/1000); 
	append_to_json(jsonbuf, tmp);

	// %IN_PKTS Incoming flow packets (src->dst) [Aliased to %SRC_TO_DST_PKTS]
	sprintf(tmp,"\"IN_PKTS\": \"%d\", \"OUT_PKTS\": \"%d\", \"IN_BYTES\": \"%u\", \"OUT_BYTES\": \"%u\"",
			fvalue->pkts, bvalue->pkts, fvalue->bytes, bvalue->bytes);
	append_to_json(jsonbuf, tmp);

	// This may not exist in nProbe information element; TODO: check!
	sprintf(tmp,"\"IN_JITTER\": \"%lld\", \"OUT_JITTER\"; \"%lld\"",
			fvalue->jitter, bvalue->jitter);
	
	// Not present in nProbe
	sprintf(tmp,"\"SRC_FLOWLABEL\": \"%u\", \"DST_FLOWLABEL\": \"%u\"",
			fvalue->fl, bvalue->fl);
	append_to_json(jsonbuf, tmp);
	
	sprintf(tmp,"\"SRC_TOS\": \"%u\", \"DST_TOS\": \"%u\"",
			fvalue->tos, bvalue->tos);
	append_to_json(jsonbuf, tmp);

	int min_ip_pkt_len, max_ip_pkt_len;
	if( fvalue->min_pkt_len < bvalue->min_pkt_len )
		min_ip_pkt_len=fvalue->min_pkt_len;
	else
		min_ip_pkt_len=bvalue->min_pkt_len;
	if( fvalue->max_pkt_len > bvalue->max_pkt_len )
		max_ip_pkt_len=fvalue->max_pkt_len;
	else
		max_ip_pkt_len=bvalue->max_pkt_len;
	sprintf(tmp,"\"MIN_IP_PKT_LEN\": \"%u\", \"MAX_IP_PKT_LEN\": \"%u\"",
			min_ip_pkt_len, max_ip_pkt_len);
	append_to_json(jsonbuf, tmp);
	
	// Not present in nProbe
	sprintf(tmp,"\"SRC_MIN_IP_PKT_LEN\": \"%u\", \"SRC_MAX_IP_PKT_LEN\": \"%u\"",
			fvalue->min_pkt_len, fvalue->max_pkt_len);
	append_to_json(jsonbuf, tmp);
	sprintf(tmp,"\"DST_MIN_IP_PKT_LEN\": \"%u\", \"DST_MAX_IP_PKT_LEN\": \"%u\"",
			bvalue->min_pkt_len, bvalue->max_pkt_len);
	append_to_json(jsonbuf, tmp);

	sprintf(tmp,"\"NUM_PKTS_UP_TO_128_BYTES\": \"%u\", \"NUM_PKTS_128_TO_256_BYTES\": \"%u\", \"NUM_PKTS_256_TO_512_BYTES\": \"%u\", \"NUM_PKTS_512_TO_1024_BYTES\": \"%u\", \"NUM_PKTS_1024_TO_1514_BYTES\": \"%u\", \"NUM_PKTS_OVER_1514_BYTES\": \"%u\"",
			fvalue->pkt_size_hist[0]+bvalue->pkt_size_hist[0],
			fvalue->pkt_size_hist[1]+bvalue->pkt_size_hist[1],
			fvalue->pkt_size_hist[2]+bvalue->pkt_size_hist[2],
			fvalue->pkt_size_hist[3]+bvalue->pkt_size_hist[3],
			fvalue->pkt_size_hist[4]+bvalue->pkt_size_hist[4],
			fvalue->pkt_size_hist[5]+bvalue->pkt_size_hist[5]);
	append_to_json(jsonbuf, tmp);

	// Not present in nProbe
	sprintf(tmp,"\"SRC_NUM_PKTS_UP_TO_128_BYTES\": \"%u\", \"SRC_NUM_PKTS_128_TO_256_BYTES\": \"%u\", \"SRC_NUM_PKTS_256_TO_512_BYTES\": \"%u\", \"SRC_NUM_PKTS_512_TO_1024_BYTES\": \"%u\", \"SRC_NUM_PKTS_1024_TO_1514_BYTES\": \"%u\", \"SRC_NUM_PKTS_OVER_1514_BYTES\": \"%u\"",fvalue->pkt_size_hist[0],fvalue->pkt_size_hist[1],fvalue->pkt_size_hist[2],fvalue->pkt_size_hist[3],fvalue->pkt_size_hist[4],fvalue->pkt_size_hist[5]);
	append_to_json(jsonbuf, tmp);
	sprintf(tmp,"\"DST_NUM_PKTS_UP_TO_128_BYTES\": \"%u\", \"DST_NUM_PKTS_128_TO_256_BYTES\": \"%u\", \"DST_NUM_PKTS_256_TO_512_BYTES\": \"%u\", \"DST_NUM_PKTS_512_TO_1024_BYTES\": \"%u\", \"DST_NUM_PKTS_1024_TO_1514_BYTES\": \"%u\", \"DST_NUM_PKTS_OVER_1514_BYTES\": \"%u\"",bvalue->pkt_size_hist[0],bvalue->pkt_size_hist[1],bvalue->pkt_size_hist[2],bvalue->pkt_size_hist[3],bvalue->pkt_size_hist[4],bvalue->pkt_size_hist[5]);
	append_to_json(jsonbuf, tmp);

	int min_ttl, max_ttl;
	if( fvalue->min_ttl < bvalue->min_ttl )
		min_ttl=fvalue->min_ttl;
	else
		min_ttl=bvalue->min_ttl;
	if( fvalue->max_ttl > bvalue->max_ttl )
		max_ttl=fvalue->max_ttl;
	else
		max_ttl=bvalue->max_ttl;
	sprintf(tmp,"\"MIN_TTL\": \"%u\", \"MAX_TTL\": \"%u\"",min_ttl, max_ttl);
	append_to_json(jsonbuf, tmp);

	sprintf(tmp,"\"NUM_PKTS_TTL_EQ_1\": \"%u\", \"NUM_PKTS_TTL_2_5\": \"%u\", \"NUM_PKTS_TTL_5\": \"%u\", \"NUM_PKTS_TTL_32_64\": \"%u\", \"NUM_PKTS_TTL_64_96\": \"%u\", \"NUM_PKTS_TTL_96_128\": \"%u\", \"NUM_PKTS_TTL_128_160\": \"%u\", \"NUM_PKTS_TTL_160_192\": \"%u\", \"NUM_PKTS_TTL_192_224\": \"%u\", \"NUM_PKTS_TTL_224_255\": \"%u\"", 
		fvalue->pkt_ttl_hist[0]+bvalue->pkt_ttl_hist[0],
		fvalue->pkt_ttl_hist[1]+bvalue->pkt_ttl_hist[1],
		fvalue->pkt_ttl_hist[2]+bvalue->pkt_ttl_hist[2],
		fvalue->pkt_ttl_hist[3]+bvalue->pkt_ttl_hist[3],
		fvalue->pkt_ttl_hist[4]+bvalue->pkt_ttl_hist[4],
		fvalue->pkt_ttl_hist[5]+bvalue->pkt_ttl_hist[5],
		fvalue->pkt_ttl_hist[6]+bvalue->pkt_ttl_hist[6],
		fvalue->pkt_ttl_hist[7]+bvalue->pkt_ttl_hist[7],
		fvalue->pkt_ttl_hist[8]+bvalue->pkt_ttl_hist[8],
		fvalue->pkt_ttl_hist[9]+bvalue->pkt_ttl_hist[9]);
	append_to_json(jsonbuf, tmp);

	// Not present in nProbe
	sprintf(tmp,"\"SRC_MIN_TTL\": \"%u\", \"SRC_MAX_TTL\": \"%u\"",fvalue->min_ttl, fvalue->max_ttl);
	append_to_json(jsonbuf, tmp);
	sprintf(tmp,"\"DST_MIN_TTL\": \"%u\", \"DST_MAX_TTL\": \"%u\"",bvalue->min_ttl, bvalue->max_ttl);
	append_to_json(jsonbuf, tmp);
	sprintf(tmp,"\"SRC_NUM_PKTS_TTL_EQ_1\": \"%u\", \"SRC_NUM_PKTS_TTL_2_5\": \"%u\", \"SRC_NUM_PKTS_TTL_5\": \"%u\", \"SRC_NUM_PKTS_TTL_32_64\": \"%u\", \"SRC_NUM_PKTS_TTL_64_96\": \"%u\", \"SRC_NUM_PKTS_TTL_96_128\": \"%u\", \"SRC_NUM_PKTS_TTL_128_160\": \"%u\", \"SRC_NUM_PKTS_TTL_160_192\": \"%u\", \"SRC_NUM_PKTS_TTL_192_224\": \"%u\", \"SRC_NUM_PKTS_TTL_224_255\": \"%u\"", 
		fvalue->pkt_ttl_hist[0],
		fvalue->pkt_ttl_hist[1],
		fvalue->pkt_ttl_hist[2],
		fvalue->pkt_ttl_hist[3],
		fvalue->pkt_ttl_hist[4],
		fvalue->pkt_ttl_hist[5],
		fvalue->pkt_ttl_hist[6],
		fvalue->pkt_ttl_hist[7],
		fvalue->pkt_ttl_hist[8],
		fvalue->pkt_ttl_hist[9]);
	append_to_json(jsonbuf, tmp);
	sprintf(tmp,"\"SRC_NUM_PKTS_TTL_EQ_1\": \"%u\", \"SRC_NUM_PKTS_TTL_2_5\": \"%u\", \"SRC_NUM_PKTS_TTL_5\": \"%u\", \"SRC_NUM_PKTS_TTL_32_64\": \"%u\", \"SRC_NUM_PKTS_TTL_64_96\": \"%u\", \"SRC_NUM_PKTS_TTL_96_128\": \"%u\", \"SRC_NUM_PKTS_TTL_128_160\": \"%u\", \"SRC_NUM_PKTS_TTL_160_192\": \"%u\", \"SRC_NUM_PKTS_TTL_192_224\": \"%u\", \"SRC_NUM_PKTS_TTL_224_255\": \"%u\"", 
		fvalue->pkt_ttl_hist[0],
		fvalue->pkt_ttl_hist[1],
		fvalue->pkt_ttl_hist[2],
		fvalue->pkt_ttl_hist[3],
		fvalue->pkt_ttl_hist[4],
		fvalue->pkt_ttl_hist[5],
		fvalue->pkt_ttl_hist[6],
		fvalue->pkt_ttl_hist[7],
		fvalue->pkt_ttl_hist[8],
		fvalue->pkt_ttl_hist[9]);
	append_to_json(jsonbuf, tmp);
	sprintf(tmp,"\"DST_NUM_PKTS_TTL_EQ_1\": \"%u\", \"DST_NUM_PKTS_TTL_2_5\": \"%u\", \"DST_NUM_PKTS_TTL_5\": \"%u\", \"DST_NUM_PKTS_TTL_32_64\": \"%u\", \"DST_NUM_PKTS_TTL_64_96\": \"%u\", \"DST_NUM_PKTS_TTL_96_128\": \"%u\", \"DST_NUM_PKTS_TTL_128_160\": \"%u\", \"DST_NUM_PKTS_TTL_160_192\": \"%u\", \"DST_NUM_PKTS_TTL_192_224\": \"%u\", \"DST_NUM_PKTS_TTL_224_255\": \"%u\"", 
		bvalue->pkt_ttl_hist[0],
		bvalue->pkt_ttl_hist[1],
		bvalue->pkt_ttl_hist[2],
		bvalue->pkt_ttl_hist[3],
		bvalue->pkt_ttl_hist[4],
		bvalue->pkt_ttl_hist[5],
		bvalue->pkt_ttl_hist[6],
		bvalue->pkt_ttl_hist[7],
		bvalue->pkt_ttl_hist[8],
		bvalue->pkt_ttl_hist[9]);
	append_to_json(jsonbuf, tmp);

	sprintf(tmp,"\"TCP_FLAGS\": \"%08x\"", fvalue->cumulative_flags | bvalue->cumulative_flags);
	append_to_json(jsonbuf, tmp);
	sprintf(tmp,"\"CLIENT_TCP_FLAGS\": \"%08x\", \"SERVER_TCP_FLAGS\": \"%08x\"",
			fvalue->cumulative_flags, bvalue->cumulative_flags);
	append_to_json(jsonbuf, tmp);

	sprintf(tmp,"\"RETRANSMITTED_IN_PKTS\": \"%u\", \"RETRANSMITTED_OUT_PKTS\": \"%u\", \"RETRANSMITTED_IN_BYTES\": \"%u\", \"RETRANSMITTED_OUT_BYTES\": \"%u\"", 
			fvalue->retr_pkts, 
			bvalue->retr_pkts,
			fvalue->retr_bytes,
			bvalue->retr_bytes);
	append_to_json(jsonbuf, tmp);

	sprintf(tmp,"\"OOORDER_IN_PKTS\": \"%u\", \"OOORDER_OUT_PKTS\": \"%u\"",
			fvalue->ooo_pkts, bvalue->ooo_pkts);
	append_to_json(jsonbuf, tmp);

	// Not in nProbe
	sprintf(tmp,"\"OOORDER_IN_BYTES\": \"%u\", \"OOORDER_OUT_BYTES\": \"%u\"",
			fvalue->ooo_bytes, bvalue->ooo_bytes);
	append_to_json(jsonbuf, tmp);

	sprintf(tmp,"\"TCP_WIN_MIN_IN\": \"%u\", \"TCP_WIN_MAX_IN\": \"%u\", \"TCP_WIN_MSS_IN\": \"%u\", \"TCP_WIN_SCALE_IN\": \"%u\", \"TCP_WIN_MIN_OUT\": \"%u\", \"TCP_WIN_MAX_OUT\": \"%u\", \"TCP_WIN_MSS_OUT\": \"%u\", \"TCP_WIN_SCALE_OUT\": \"%u\"",
			fvalue->min_win_bytes, fvalue->max_win_bytes, fvalue->mss, fvalue->wndw_scale,
			bvalue->min_win_bytes, bvalue->max_win_bytes, bvalue->mss, bvalue->wndw_scale);
	append_to_json(jsonbuf, tmp);


	strcpy(tmp,jsontrailer());
	append_to_json(jsonbuf, tmp);

	counter+=1;

	return jsonbuf;
}
