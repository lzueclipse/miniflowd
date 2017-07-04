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

int main (int argc, char **argv)
{
	int ch;
	pcap_t *pCap = NULL;
	int linkType, ret;
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
	
	pcap_close(pCap);
	
	return(ret == 0 ? 0 : 1);
}
