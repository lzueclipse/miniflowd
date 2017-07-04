#include "miniflowd.h"

static int verboseFlag = 0;            /* Debugging flag */


/* Datalink types that we care about */
static const struct DataLinkType lt[] = 
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
"  -i 		      Specify interface to listen on\n"
"  -D                 Debug mode\n"
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
	if(verboseFlag)
	{
		fprintf(stdout, "linkType = %s\n", (*linkType == DLT_LINUX_SLL)?"DLT_LINUX_SLL":"DLT_EN10MB");
	}
}

/*
 * Flow compare algrithom
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

	if((flowTrack->expiresList).size() == 0)
		return (-1); /* indefinite */

	//sort
	(flowTrack->expiresList).sort(ExpiresCompare);

	expire = (flowTrack->expiresList).front();
	
	expiresAt = expire.expiresAt;

	/* Don't cluster urgent expiries */
	if (expiresAt == 0 && (expire.reason == R_OVERBYTES || expire.reason == R_OVERFLOWS || expire.reason == R_FLUSH))
		return (0); /* Now */

	/* Cluster expiries*/
	if ((fudge = expiresAt % DEFAULT_EXPIRY_INTERVAL) > 0)
		expiresAt += DEFAULT_EXPIRY_INTERVAL - fudge;

	if (expiresAt < now.tv_sec)
		return (0); /* Now */

	ret = 999 + (expiresAt - now.tv_sec) * 1000;
	return (ret);
}

/*
 * Per-packet callback function from libpcap. Pass the packet (if it is IP)
 * sans datalink headers to processPacket.
 */
static void flowCallBack(uint8_t *userData, const struct pcap_pkthdr* phdr, const uint8_t *pkt)
{
	int s, af;
	int linkType = (int)*userData;
	struct timeval tv;

	s = datalink_check(cb_ctxt->linktype, pkt, phdr->caplen, &af);
	if (s < 0 || (!cb_ctxt->want_v6 && af == AF_INET6)) {
		cb_ctxt->ft->non_ip_packets++;
	} else {
		tv.tv_sec = phdr->ts.tv_sec;
		tv.tv_usec = phdr->ts.tv_usec;
		if (process_packet(cb_ctxt->ft, pkt + s, af,
		    phdr->caplen - s, phdr->len - s, &tv) == PP_MALLOC_FAIL)
			cb_ctxt->fatal = 1;
	}
}

int main (int argc, char **argv)
{
	int ch;
	pcap_t *pCap = NULL;
	int linkType, ret;
	struct pollfd pollFd[1];
	FlowTrack flowTrack;

	while ((ch = getopt(argc, argv, "hD")) != -1) 
	{
		switch (ch) 
		{
		case 'h':
			usage();
			return (0);
		case 'D':
			verboseFlag = 1;
			break;
		default:
			fprintf(stderr, "Invalid commandline option.\n");
			usage();
			exit(1);
		}
	}

	/* Will exit on failure */
	setupPacketCapture(&pCap, &linkType);
	
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
			ret = pcap_dispatch(pCap, -1, flowCallBack,(void*)&linkType);
			if (ret == -1) {
				fprintf(stderr, "Exiting on pcap_dispatch: %s", pcap_geterr(pCap));
				break;
			}
		}
	
	}
	pcap_close(pCap);

#if 0
	Flow tmp1, tmp2, tmp3;
	tmp1.af=100;
	tmp1.expiresAt=1;
	tmp1.flowSeq=3;
	tmp2.af=100;
	tmp2.expiresAt=1;
	tmp2.flowSeq=2;
	tmp3.af=90;
	tmp3.expiresAt=1;
	tmp3.flowSeq=1;
        std::list<Flow> expiresSet; 
	expiresSet.push_back(tmp1);
	expiresSet.push_back(tmp2);
	expiresSet.push_back(tmp3);

	expiresSet.sort(ExpiresCompare);
	for(std::list<Flow>::iterator it = expiresSet.begin(); it!=expiresSet.end(); ++it)
	{
		std::cout << it->af <<", " << it->expiresAt << "," << it->flowSeq<< std::endl;
	}
#endif

	return(ret == 0 ? 0 : 1);
}
