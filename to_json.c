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

#define JSONBUFSIZE 2048

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
		if( jsonbuf[len-1] != '{' )
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

	long int last_seen = 0;
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
	
	strcat(jsonbuf, jsontrailer());

	counter+=1;

	return jsonbuf;
}
