#include "miniflowd.h"


static int verboseFlag = 0;            /* Debugging flag */
static int elasticFlag = 0;            /* elasticsearch flag */


/* Datalink types that we care about */
static const struct DataLinkType dataLinkTypeArray[] = 
{
	//Normal Ethenet
	{ DLT_EN10MB,	14, 12,  2,  1, 0xffffffff,  0x0800,   0x86dd },
	//Linux cooked, "any interfaces"
	{ DLT_LINUX_SLL,16, 14,  2,  1, 0xffffffff,  0x0800,   0x86dd },
};

/* Display commandline usage information */
static void usage(void)
{
	fprintf(stderr, 
"Usage: miniflowd [options] \n"
"  -D                 Debug mode\n"
"  -E                 Elasticsearch mode\n"
"  -h                 Display this help\n"
"\n"
"Valid timeout names and default values:\n"
"  tcp     (default %6d)"
"  tcp.rst (default %6d)"
"  tcp.fin (default %6d)\n"
"  udp     (default %6d)"
"  icmp    (default %6d)"
"  general (default %6d)\n"
"  maxlife (default %6d)"
"  expint  (default %6d)\n"
"\n" ,
	    DEFAULT_TCP_TIMEOUT, DEFAULT_TCP_RST_TIMEOUT,
	    DEFAULT_TCP_FIN_TIMEOUT, DEFAULT_UDP_TIMEOUT, DEFAULT_ICMP_TIMEOUT,
	    DEFAULT_GENERAL_TIMEOUT, DEFAULT_MAXIMUM_LIFETIME,
	    DEFAULT_EXPIRY_INTERVAL);
}

static void setupPacketCapture(struct pcap **pCap, int *linkType)
{
	char eBuf[PCAP_ERRBUF_SIZE];

	/* Open pcap, all interfaces... */
	if ((*pCap = pcap_open_live(NULL, LIBPCAP_SNAPLEN_V4, 1, 0, eBuf)) == NULL) 
	{
		fprintf(stderr, "pcap_open_live: %s\n", eBuf);
		exit(1);
	}
	*linkType = pcap_datalink(*pCap);
	//Only support Normal Ethernet, Linux cooked sockets(any interfaces)
	if (*linkType != DLT_LINUX_SLL && *linkType != DLT_EN10MB)
	{
		fprintf(stderr, "Unsupported datalink type %d\n", *linkType);
		exit(1);
	}
		
	fprintf(stdout, "linkType = %s\n", (*linkType == DLT_LINUX_SLL)?"DLT_LINUX_SLL":"DLT_EN10MB");
}

/*
 * Expired Flow compare algrithom
 */
bool ExpiresCompare(const Flow &left, const Flow &right)
{
	/*Sorting, First expires time */
        if (left.expiresAt != right.expiresAt)
	{
       	        return (left.expiresAt < right.expiresAt);
	}

       	/* Then flow sequence */
       	if (left.flowSeq != right.flowSeq)
	{
               	return (left.flowSeq < right.flowSeq);
	}

	return false;
}

/* How long before the next expiry event in millisecond */
static int nextExpire(FlowTrack *flowTrack)
{
	struct timeval now;
	uint32_t expiresAt, ret, fudge;
	Flow expire;
	
	gettimeofday(&now, NULL);

	if((flowTrack->flowsList).size() == 0)
	{
		return (-1); /* indefinite */
	}

	//sort
	(flowTrack->flowsList).sort(ExpiresCompare);
	
	expire = (flowTrack->flowsList).front();
	
	expiresAt = expire.expiresAt;
		
	/* Don't cluster urgent expiries */
	if (expiresAt == 0 && (expire.reason == R_OVERBYTES || expire.reason == R_OVERFLOWS || expire.reason == R_FLUSH))
	{
		if(verboseFlag)
		{
			//fprintf(stdout, "Expire immediately\n");
		}
		return (0); /* Now */
	}

	/* Cluster expiries*/
	if (expiresAt < now.tv_sec)
	{
		if(verboseFlag)
		{
			//fprintf(stdout, "Expire immediately\n");
		}
		return (0); /* Now */
	}

	ret = 999 + (expiresAt - now.tv_sec) * 1000;
	if(verboseFlag)
	{
		//fprintf(stdout, "nextExpire time = %u ms\n", ret );
	}
	return (ret);
}

/*
 * Figure out how many bytes to skip from front of packet to get past 
 * datalink headers. If pkt is specified, also check whether determine
 * whether or not it is one that we are interested in (IPv4 or IPv6 for now)
 *
 * Returns number of bytes to skip or -1 to indicate that entire 
 * packet should be skipped
 */
static int dataLinkCheck(int linkType, const uint8_t *pkt, uint32_t capLen, int *af)
{
	int i, j;
	uint32_t frameType;
	DataLinkType *tmpType = NULL;
		
	for (i = 0; i< (sizeof(dataLinkTypeArray)/sizeof(DataLinkType)); i++)
	{
		if (dataLinkTypeArray[i].dataLinkType == linkType)
		{
			tmpType = (DataLinkType *)&(dataLinkTypeArray[i]);
		}
	}

	if(tmpType == NULL)
	{
		fprintf(stderr, "tmpType is NULL\n");
		return (-1);
	}
	if (pkt == NULL)
	{
		fprintf(stderr, "pkt is NULL\n");
		return (-1);
	}
	if (capLen <= tmpType->skipLen)
	{
		fprintf(stderr, "capLen is to short\n");
		return (-1);
	}

	/* Suck out the frametype */
	frameType = 0;
	if (tmpType->frameTypeBigEndian) 
	{
		for (j = 0; j < tmpType->frameTypeLen; j++) 
		{
			frameType <<= 8;
			frameType |= pkt[j + tmpType->frameTypeOffset];
		}
	} else {
		for (j = tmpType->frameTypeLen - 1; j >= 0 ; j--) {
			frameType <<= 8;
			frameType |= pkt[j + tmpType->frameTypeOffset];
		}
	}
	frameType &= tmpType->frameTypeMask;

	if (frameType == tmpType->frameTypeV4)
		*af = AF_INET;
	else if (frameType == tmpType->frameTypeV4)
		*af = AF_INET6;
	else
	{
		return (-1);
	}
	
	//jump to IP header
	return (tmpType->skipLen);
}

/* Fill in transport-layer (tcp/udp) portions of flow record */
static int
tcpUdpToFlow(Flow *flow, const uint8_t *pkt, const size_t capLen, int isFrag, int protocol, int ndx)
{
	const struct tcphdr *tcp = (const struct tcphdr *)pkt;
	const struct udphdr *udp = (const struct udphdr *)pkt;
	const struct icmp *icmp = (const struct icmp *)pkt;

	/*
	 * XXX to keep flow in proper canonical format, it may be necessary to
	 * swap the array slots based on the order of the port numbers does
	 * this matter in practice??? I don't think so - return flows will
	 * always match, because of their symmetrical addr/ports
	 */

	switch (protocol) 
	{
	case IPPROTO_TCP:
		/* Check for runt packet, but don't error out on short frags */
		if (capLen < sizeof(*tcp))
		{
			return (isFrag ? 0 : -1);
		}
		flow->port[ndx] = tcp->source;
		flow->port[ndx ^ 1] = tcp->dest;
		flow->tcpRst[ndx] = tcp->rst;
		flow->tcpFin[ndx] = tcp->fin;
		break;
	case IPPROTO_UDP:
		/* Check for runt packet, but don't error out on short frags */
		if (capLen < sizeof(*udp))
		{
			return (isFrag ? 0 : -1);
		}
		flow->port[ndx] = udp->source;
		flow->port[ndx ^ 1] = udp->dest;
		break;
	case IPPROTO_ICMP:
		/*
		 * Encode ICMP type * 256 + code into dest port like
		 * Cisco routers
		 */
		flow->port[ndx] = 0;
		flow->port[ndx ^ 1] = htons(icmp->icmp_type * 256 +
		    icmp->icmp_code);
		break;
	}
	return (0);
}

/* Convert a IPv4 packet to a partial flow record (used for comparison) */
static int ipv4ToFlow(Flow *flow, const uint8_t *pkt, size_t capLen, size_t len, int *isfrag, int af)
{
	const struct ip *ip = (const struct ip *)pkt;
	int ndx;
	int ret;

	//IP header length unit: 4 Bytes
	if (capLen < 20 || capLen < ip->ip_hl * 4)
	{
		return (-1);	/* Runt packet */
	}
	if (ip->ip_v != 4)
	{
		return (-1);	/* Unsupported IP version */
	}
	
	/* Prepare to store flow in canonical format */
	ndx = memcmp(&ip->ip_src, &ip->ip_dst, sizeof(ip->ip_src)) > 0 ? 1 : 0;
	
	flow->af = af;
	flow->addr[ndx] = ip->ip_src;
	flow->addr[ndx ^ 1] = ip->ip_dst;
	flow->protocol = ip->ip_p;
	flow->octets[ndx] = len;
	flow->packets[ndx] = 1;

	*isfrag = (ntohs(ip->ip_off) & (IP_OFFMASK|IP_MF)) ? 1 : 0;

	/* if not first fragment, there is no TCP/UDP header */
	/* Don't try to examine higher level headers if not first fragment */
	if (*isfrag && (ntohs(ip->ip_off) & IP_OFFMASK) != 0)
	{
		return (0);
	}

	//IP header length unit: 4 Bytes
	ret = tcpUdpToFlow(flow, pkt + (ip->ip_hl * 4), capLen - (ip->ip_hl * 4), *isfrag, ip->ip_p, ndx);
	return ret;
}

static const char * protocolToStr(uint8_t protocol)
{
	static char protobuf[64];
	memset(protobuf, 0, sizeof(protobuf));
	
	if(protocol == IPPROTO_IP)
	{
		strcat(protobuf, "IP");
	}
	else if(protocol == IPPROTO_TCP)
	{
		strcat(protobuf, "TCP");
	}
	else if(protocol == IPPROTO_ICMP)
	{
		strcat(protobuf, "ICMP");
	}
	else if(protocol == IPPROTO_UDP)
	{
		strcat(protobuf, "UDP");
	}
	else if(protocol == IPPROTO_IGMP)
	{
		strcat(protobuf, "IGMP");
	}
	else if(protocol == IPPROTO_IPV6)
	{
		strcat(protobuf, "IPV6");
	}
	else if(protocol == IPPROTO_GRE)
	{
		strcat(protobuf, "GRE");
	}
	else if(protocol == IPPROTO_ICMPV6)
	{
		strcat(protobuf, "ICMPV6");
	}
	else 
	{
		strcat(protobuf, "OTHERS");
	}
	return protobuf;
}

static char *expireReason(int reason)
{
	static char reasonBuf[64];
	memset(reasonBuf, 0, sizeof(reasonBuf));
	if(reason == R_GENERAL)
	{
		strcat(reasonBuf, "R_GENERAL");
	}
	else if(reason == R_TCP)
	{
		strcat(reasonBuf, "R_TCP");
	}
	else if(reason == R_TCP_RST)
	{
		strcat(reasonBuf, "R_TCP_RST");
	}
	else if(reason == R_TCP_FIN)
	{
		strcat(reasonBuf, "R_TCP_FIN");
	}
	else if(reason == R_UDP)
	{
		strcat(reasonBuf, "R_UDP");
	}
	else if(reason == R_ICMP)
	{
		strcat(reasonBuf, "R_ICMP");
	}
	else if(reason == R_MAXLIFE)
	{
		strcat(reasonBuf, "R_MAXLIFE");
	}
	else if(reason == R_OVERBYTES)
	{
		strcat(reasonBuf, "R_OVERFLOWS");
	}
	else if(reason == R_FLUSH)
	{
		strcat(reasonBuf, "R_FLUSH");
	}
	else
	{
		strcat(reasonBuf, "OTHERS");
	}
	
}

/* Format a time format */
static const char * formatTime(time_t t)
{
	struct tm *tm;
	static char buf[32];

	tm = gmtime(&t);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", tm);

	return (buf);

}

/* Format a flow in a brief way */
static const char * formatFlowBrief(Flow *flow)
{
	char addr1[64], addr2[64];
	static char buf[1024];

	inet_ntop(flow->af, &flow->addr[0], addr1, sizeof(addr1));
	inet_ntop(flow->af, &flow->addr[1], addr2, sizeof(addr2));
	snprintf(buf, sizeof(buf), "seq:%" PRIu64 " [%s]:%hu <> [%s]:%hu proto:%u, %s",
	    flow->flowSeq,
	    addr1, ntohs(flow->port[0]), addr2, ntohs(flow->port[1]),
	    (int)flow->protocol, protocolToStr(flow->protocol));
	
	return (buf);
}

/* Format a flow in a verbose  way */
static const char * formatFlow(Flow *flow)
{
	char addr1[64], addr2[64], sTime[32], fTime[32];
	static char buf[1024];

	inet_ntop(flow->af, &flow->addr[0], addr1, sizeof(addr1));
	inet_ntop(flow->af, &flow->addr[1], addr2, sizeof(addr2));

	snprintf(sTime, sizeof(sTime), "%s", formatTime(flow->flowStart.tv_sec));
	snprintf(fTime, sizeof(fTime), "%s", formatTime(flow->flowLast.tv_sec));

	snprintf(buf, sizeof(buf),  "seq:%" PRIu64" [%s]:%hu <> [%s]:%hu proto:%u,%s " \
		"octets>:%" PRIu64 " packets>:%" PRIu64 " octets<:%" PRIu64 " packets<:%" PRIu64 \
	    	" start:%s.%03ld finish:%s.%03ld tcp.rst>:%d tcp.fin>:%d  tcp.rst<:%d tcp.fin<%d reason:%s\n", \
	    	flow->flowSeq,  \
		addr1, ntohs(flow->port[0]), \
		addr2, ntohs(flow->port[1]), \
	    	(int)flow->protocol, protocolToStr(flow->protocol),\
	    	flow->octets[0], flow->packets[0], \
	    	flow->octets[1], flow->packets[1], \
	    	sTime, (flow->flowStart.tv_usec + 500) / 1000, \
	    	fTime, (flow->flowLast.tv_usec + 500) / 1000, \
		flow->tcpRst[0], flow->tcpFin[0], \
		flow->tcpRst[1], flow->tcpFin[1], \
		expireReason(flow->reason)
	    );

	return (buf);
}

static void flowUpdateExpiry(Flow *flow)
{

	/* Flows over maximum life seconds */
	if (flow->flowLast.tv_sec - flow->flowStart.tv_sec > DEFAULT_MAXIMUM_LIFETIME) 
	{
		flow->expiresAt = 0;
		flow->reason = R_MAXLIFE;
		goto out;
	}
	
	if (flow->protocol == IPPROTO_TCP)
	{
		/* Reset TCP flows */
		if ( (flow->tcpRst[0] == 1) || (flow->tcpRst[1] == 1 )) 
		{
			flow->expiresAt = flow->flowLast.tv_sec + DEFAULT_TCP_RST_TIMEOUT;
			flow->reason = R_TCP_RST;
			goto out;
		}
		/* Finished TCP flows */
		if ((flow->tcpFin[0] == 1) || (flow->tcpFin[1] == 1))
		{
			flow->expiresAt = flow->flowLast.tv_sec + DEFAULT_TCP_FIN_TIMEOUT;
			flow->reason = R_TCP_FIN;
			goto out;
		}

		/* TCP flows */
		flow->expiresAt = flow->flowLast.tv_sec + DEFAULT_TCP_TIMEOUT;
		flow->reason = R_TCP;
		goto out;
	}

	if (flow->protocol == IPPROTO_UDP) 
	{
		/* UDP flows */
		flow->expiresAt = flow->flowLast.tv_sec + DEFAULT_UDP_TIMEOUT;
		flow->reason = R_UDP;
		goto out;
	}

	if (flow->af == AF_INET && flow->protocol == IPPROTO_ICMP) 
	{ 
		/* ICMP flows */
		flow->expiresAt = flow->flowLast.tv_sec + DEFAULT_ICMP_TIMEOUT;
		flow->reason = R_ICMP;
		goto out;
	}

	/* Everything else */
	flow->expiresAt = flow->flowLast.tv_sec + DEFAULT_GENERAL_TIMEOUT;
	flow->reason = R_GENERAL;

 out:
	if (flow->expiresAt != 0) 
	{
		flow->expiresAt = std::min(flow->expiresAt, (uint32_t)(flow->flowStart.tv_sec + DEFAULT_MAXIMUM_LIFETIME));
	}

}


/*
 * Main per-packet processing function. Take a packet (provided by 
 * libpcap) and attempt to find a matching flow. If no such flow exists, 
 * then create one. 
 *
 * Also marks flows for fast expiry, based on flow or packet attributes
 * (the actual expiry is performed elsewhere)
 */
static int processPacket(FlowTrack *flowTrack, const uint8_t *pkt, int af, const u_int32_t capLen, const uint32_t len, 
    const struct timeval *receivedTime)
{
	Flow tmpFlow;
	int frag;
	int ret;
	bool found;

	/* Convert the IP packet to a flow identity */
	if(af == AF_INET) 
	{	
		//IPv4
		ret = ipv4ToFlow(&tmpFlow, pkt, capLen, len, &frag, af);
	}

	std::list<Flow>::iterator it = flowTrack->flowsList.begin();
	for(; it!=flowTrack->flowsList.end(); ++it)
	{
		//operator ==
		if( (*it) == tmpFlow)
		{
			found = true;
			break;
		}
	}

	/* If a matching flow does not exist, create and insert one */
	if(!found)
	{
		memcpy(&(tmpFlow.flowStart), receivedTime, sizeof(tmpFlow.flowStart));
		tmpFlow.flowSeq = flowTrack->nextFlowSeq++;
		fprintf(stdout, "Add Flow %s\n", formatFlowBrief(&tmpFlow));
		memcpy(&(tmpFlow.flowLast), receivedTime, sizeof(tmpFlow.flowLast));
		/* Must be non-zero (0 means expire immediately) */
		tmpFlow.expiresAt = 1;
		tmpFlow.reason = R_GENERAL;
		flowUpdateExpiry(&tmpFlow);
		flowTrack->flowsList.push_back(tmpFlow);
	}
	else
	{
		/* Update flow statistics */
		it->packets[0] += tmpFlow.packets[0];
		it->octets[0] += tmpFlow.octets[0];
		if(tmpFlow.tcpFin[0] == 1)
			it->tcpFin[0] = 1; //keep it
		if(tmpFlow.tcpRst[0] == 1)
			it->tcpRst[0] = 1; //keep it

		it->packets[1] += tmpFlow.packets[1];
		it->octets[1] += tmpFlow.octets[1];
		if(tmpFlow.tcpFin[1] == 1)
			it->tcpFin[1] = 1; //keep it
		if(tmpFlow.tcpRst[1] == 1)
			it->tcpRst[1] = 1; //keep it
		memcpy(&(it->flowLast), receivedTime, sizeof(it->flowLast));
		flowUpdateExpiry(&(*it));
	}
	
	return 0;
}
/*
 * Per-packet callback function from libpcap. Pass the packet (if it is IP)
 * sans datalink headers to processPacket.
 */
static void flowCallBack(uint8_t *userData, const struct pcap_pkthdr* phdr, const uint8_t *pkt)
{
	int ret, af;
	struct timeval tv;
	FlowTrack *flowTrack = (FlowTrack *)userData;

	ret = dataLinkCheck(flowTrack->linkType, pkt, phdr->caplen, &af);
	if (ret < 0 || af == AF_INET6) 
	{
		//IPv6 not support for now
	}
	else 
	{	
		//IPv4
		tv.tv_sec = phdr->ts.tv_sec;
		tv.tv_usec = phdr->ts.tv_usec;
		//Skip Data link header
		ret = processPacket(flowTrack, pkt + ret, af, phdr->caplen - ret, phdr->len - ret, &tv);
	}
}

void generateElasticScript(Flow *flow)
{
	char addr0[64], addr1[64], sTime[32], fTime[32];
	char restfulBuf[2048];
	char *ipv4Src = NULL, *ipv4Dst = NULL;
	char hostname[1024];
	uint16_t portSrc, portDst;
	struct timeval now;
	static char *url = "curl -XPOST 'http://localhost:9200/my_index/my_flows/?pretty' -H 'Content-Type: application/json' -d";
	//ipv4 for now
	if(flow->af != AF_INET)
		return;    

	gettimeofday(&now, NULL);
	gethostname(hostname, sizeof(hostname));	

	inet_ntop(flow->af, &flow->addr[0], addr0, sizeof(addr0));
	inet_ntop(flow->af, &flow->addr[1], addr1, sizeof(addr1));

	snprintf(sTime, sizeof(sTime), "%s", formatTime(flow->flowStart.tv_sec));
	snprintf(fTime, sizeof(fTime), "%s", formatTime(flow->flowLast.tv_sec));
	
	if( flow->packets[0] > 0)
	{
		ipv4Src = addr0;
		ipv4Dst = addr1;
		portSrc = ntohs(flow->port[0]);
		portDst = ntohs(flow->port[1]);
		snprintf(restfulBuf, sizeof(restfulBuf), "%s \'\n" 
"{\n " \
"\t\"@timestamp\"            : %" PRIu64 ",\n " \
"\t\"agent_host_name\"       : \"%s\",\n " \
"\t\"ipv4_dst_addr\"         : \"%s\",\n " \
"\t\"ipv4_src_addr\"         : \"%s\",\n " \
"\t\"l4_dst_port\"           : %u,\n " \
"\t\"l4_src_port\"           : %u,\n " \
"\t\"has_tcp_fin\"           : %u,\n " \
"\t\"has_tcp_rst\"           : %u,\n " \
"\t\"protocol\"              : %u,\n " \
"\t\"protocol_text\"         : \"%s\",\n " \
"\t\"start_time\"        : %" PRIu64 ",\n " \
"\t\"first_switched_text\"   : \"%s\",\n " \
"\t\"last_switched\"         : %" PRIu64 ",\n " \
"\t\"last_switched_text\"    : \"%s\",\n " \
"\t\"in_bytes\"              : %u,\n " \
"\t\"in_pkts\"               : %u\n " \
"} \n\'",url, (uint64_t)(now.tv_sec) * 1000, hostname, ipv4_dst, ipv4_src, port_dst, port_src, flow->tcp_flags[0], \
tcp_flags_text, tcp_flags_rst, flow->protocol, protocol_to_str(flow->protocol), (uint64_t)(flow->flow_start.tv_sec) * 1000 , stime, \
(uint64_t)(flow->flow_last.tv_sec) * 1000, ftime, flow->octets[0], flow->packets[0]);
	
		logit(LOG_DEBUG,"%s\n",resetbuf);
		system(resetbuf);
	}
	
	if( flow->packets[1] > 0)
	{
		ipv4_src = addr1;
		ipv4_dst = addr0;
		port_src = ntohs(flow->port[1]);
		port_dst = ntohs(flow->port[0]);
		memset(tcp_flags_text, 0, sizeof(tcp_flags_text));
		strcat(tcp_flags_text, tcp_flags_to_str(flow->tcp_flags[1]));
		tcp_flags_rst = 0;
		if(flow->tcp_flags[1] & TH_RST)
		{
			tcp_flags_rst = 1;
		}
		
		snprintf(resetbuf, sizeof(resetbuf), "%s \'\n" 
"{\n " \
"\t\"@timestamp\"            : %" PRIu64 ",\n " \
"\t\"agent_host_name\"       : \"%s\",\n " \
"\t\"ipv4_dst_addr\"         : \"%s\",\n " \
"\t\"ipv4_src_addr\"         : \"%s\",\n " \
"\t\"l4_dst_port\"           : %u,\n " \
"\t\"l4_src_port\"           : %u,\n " \
"\t\"tcp_flags\"             : %u,\n " \
"\t\"tcp_flags_text\"        : \"%s\",\n " \
"\t\"has_tcp_rst\"           : %u,\n " \
"\t\"protocol\"              : %u,\n " \
"\t\"protocol_text\"         : \"%s\",\n " \
"\t\"first_switched\"        : %" PRIu64 ",\n " \
"\t\"first_switched_text\"   : \"%s\",\n " \
"\t\"last_switched\"         : %" PRIu64 ",\n " \
"\t\"last_switched_text\"    : \"%s\",\n " \
"\t\"in_bytes\"              : %u,\n " \
"\t\"in_pkts\"               : %u\n " \
"} \n\'",url, (uint64_t)(now.tv_sec) * 1000, hostname, ipv4_dst, ipv4_src, port_dst, port_src, flow->tcp_flags[1], tcp_flags_text, tcp_flags_rst,\
flow->protocol, protocol_to_str(flow->protocol), (uint64_t)(flow->flow_start.tv_sec) * 1000, stime, (uint64_t)(flow->flow_last.tv_sec) * 1000, \
ftime, flow->octets[1], flow->packets[1]);
	
		logit(LOG_DEBUG,"%s\n",resetbuf);
		system(resetbuf);
	}

#endif
}

static int flowExpire(FlowTrack *flowTrack)
{
	int numExpired = 0;
	struct timeval now;

	gettimeofday(&now, NULL);
	
	//already sorted...
	std::list<Flow>::iterator it = flowTrack->flowsList.begin();
	while(it!=flowTrack->flowsList.end())
	{
		if(it->expiresAt == 0 || it->expiresAt < now.tv_sec)
		{
			/* Flow has expired */
			if(it->flowStart.tv_sec - it->flowLast.tv_sec > DEFAULT_MAXIMUM_LIFETIME)
			{
				it->reason = R_MAXLIFE;
			}
			
			
			fprintf(stdout, "Del flow %s\n", formatFlow(&(*it)) );
			
			if (elasticFlag)
			{
				generateElasticScript(&(*it));
			}
			
			numExpired++;
			//pop it
			flowTrack->flowsList.pop_front();
			//begin
			it = flowTrack->flowsList.begin();
		}
		else
		{
			++it;
		}
	}
	

	return (numExpired);
}

int main (int argc, char **argv)
{
	int ch;
	pcap_t *pCap = NULL;
	int ret;
	static FlowTrack flowTrack;
	struct pollfd pollFd[1];
	while ((ch = getopt(argc, argv, "hDE")) != -1) 
	{
		switch (ch) 
		{
		case 'h':
			usage();
			return (0);
		case 'D':
			verboseFlag = 1;
		case 'E':
			elasticFlag = 1;
			break;
		default:
			fprintf(stderr, "Invalid commandline option.\n");
			usage();
			exit(1);
		}
	}

	/* Will exit on failure */
	setupPacketCapture(&pCap, &(flowTrack.linkType));
	
	while(1)
	{
		memset(pollFd, 0, sizeof(pollFd));
		pollFd[0].events = POLLIN|POLLERR|POLLHUP;
                pollFd[0].fd = pcap_fileno(pCap);
		
		ret = poll(pollFd, 1, nextExpire(&flowTrack));

		if (ret == -1 && errno != EINTR) {
			fprintf(stderr, "Exiting on poll: %s", strerror(errno));
			break;
		}
		
		/* If we have data, run it through libpcap */
		if(pollFd[0].revents != 0) 
		{
			ret = pcap_dispatch(pCap, -1, flowCallBack,(u_char *)&flowTrack);
			if (ret == -1) 
			{
				fprintf(stderr, "Exiting on pcap_dispatch: %s", pcap_geterr(pCap));
				break;
			}
		}
		
		if(nextExpire(&flowTrack)== 0)
		{
			flowExpire(&flowTrack);
		}
	
	}
	pcap_close(pCap);

	return(ret == 0 ? 0 : 1);
}
