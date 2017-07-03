#include "miniflowd.h"

static int verbose_flag = 0;            /* Debugging flag */


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

static void setup_packet_capture(struct pcap **pcap, int *linktype, char *dev)
{
	char ebuf[PCAP_ERRBUF_SIZE];
	uint32_t bpf_mask, bpf_net;

	/* Open pcap */
	if (dev != NULL) 
	{
		if ((*pcap = pcap_open_live(dev, LIBPCAP_SNAPLEN_V4, 1, 0, ebuf)) == NULL) 
		{
			fprintf(stderr, "pcap_open_live: %s\n", ebuf);
			exit(1);
		}
		if (pcap_lookupnet(dev, &bpf_net, &bpf_mask, ebuf) == -1)
			bpf_net = bpf_mask = 0;
	}
	*linktype = pcap_datalink(*pcap);
	if (datalink_check(*linktype, NULL, 0, NULL) == -1) {
		fprintf(stderr, "Unsupported datalink type %d\n", *linktype);
		exit(1);
	}

#ifdef BIOCLOCK
	/*
	 * If we are reading from an device (not a file), then 
	 * lock the underlying BPF device to prevent changes in the 
	 * unprivileged child
	 */
	if (dev != NULL && ioctl(pcap_fileno(*pcap), BIOCLOCK) < 0) {
		fprintf(stderr, "ioctl(BIOCLOCK) failed: %s\n",
		    strerror(errno));
		exit(1);
	}
#endif
}

int main (int argc, char **argv)
{
	int ch;
	pcap_t *pcap = NULL;
	char *dev;
	int linktype, ret;
	while ((ch = getopt(argc, argv, "hD:i:")) != -1) 
	{
		switch (ch) 
		{
		case 'h':
			usage();
			return (0);
		case 'D':
			verbose_flag = 1;
			/* FALLTHROUGH */
		case 'i':
			dev = strsep(&optarg, ":");
			if (verbose_flag)
				fprintf(stderr, "Using %s \n", dev);
			break;
		default:
			fprintf(stderr, "Invalid commandline option.\n");
			usage();
			exit(1);
		}
	}

	/* Will exit on failure */
	setup_packet_capture(&pcap, &linktype, dev);
	
	pcap_close(pcap);
	
	return(ret == 0 ? 0 : 1);
}
	
