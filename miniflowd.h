#ifndef _MINIFLOWD_H
#define _MINIFLOWD_H

#include <set>

#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netdb.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#if defined(HAVE_NET_BPF_H)
#include <net/bpf.h>
#elif defined(HAVE_PCAP_BPF_H)
#include <pcap-bpf.h>
#endif
#if defined(HAVE_INTTYPES_H)
#include <inttypes.h>
#endif


/*
 * Capture length for libpcap: Must fit the link layer header, plus 
 * a maximally sized ipv4 header and most of a TCP header
 */
#define LIBPCAP_SNAPLEN_V4	96

/*
 * Timeouts
 */
#define DEFAULT_TCP_TIMEOUT		3600
#define DEFAULT_TCP_RST_TIMEOUT		5
#define DEFAULT_TCP_FIN_TIMEOUT		5
#define DEFAULT_UDP_TIMEOUT		300
#define DEFAULT_ICMP_TIMEOUT		60
#define DEFAULT_GENERAL_TIMEOUT		3600
#define DEFAULT_MAXIMUM_LIFETIME	(3600*24*7)
#define DEFAULT_EXPIRY_INTERVAL		60

/*
 * This structure is an entry in the tree of flows that we are 
 * currently tracking. 
 *
 * Because flows are matched _bi-directionally_, they must be stored in
 * a canonical format: the numerically lowest address and port number must
 * be stored in the first address and port array slot respectively.
 */
struct Flow {
	/* Flow identity (all are in network byte order) */
	int af;					/* Address family of flow */
	struct in_addr addr[2];			/* Endpoint addresses */
	uint16_t port[2];			/* Endpoint ports */
	uint8_t tcp_flags[2];			/* Cumulative OR of flags */
	uint8_t protocol;			/* Protocol */

	/* Per-flow statistics (all in _host_ byte order) */
	uint64_t flow_seq;			/* Flow ID */
	struct timeval flow_start;		/* Time of creation */
	struct timeval flow_last;		/* Time of last traffic */

	/* Per-endpoint statistics (all in _host_ byte order) */
	uint32_t octets[2];			/* Octets so far */
	uint32_t packets[2];			/* Packets so far */
};
/*
 * Flow compare algrithom
 */
struct FlowCompare
{
	bool operator()(const struct Flow & left, const struct Flow & right) const
	{
		return true;
	}
};

/*
 * This structure is the root of the flow tracking system.
 * It holds the root of the tree of active flows and the head of the
 * tree of expiry events. It also collects miscellaneous statistics
 */
struct FlowTrack {
	/* The flows and their expiry events */
	std::set<struct Flow, FlowCompare> flowsSet;	/* Top of flow set */
	std::set<struct Flow, FlowCompare> expiriesSet;	/* Top of expiries tree */

	u_int64_t next_flow_seq;		/* Next flow ID */

	int track_level;			/* See TRACK_* above */

	/* Flow timeouts */
	int tcp_timeout;			/* Open TCP connections */
	int tcp_rst_timeout;			/* TCP flows after RST */
	int tcp_fin_timeout;			/* TCP flows after bidi FIN */
	int udp_timeout;			/* UDP flows */
	int icmp_timeout;			/* ICMP flows */
	int general_timeout;			/* Everything else */
	int maximum_lifetime;			/* Maximum life for flows */
	int expiry_interval;			/* Interval between expiries */ 

};


enum REASON
{ 
	R_GENERAL, 
	R_TCP, 
	R_TCP_RST, 
	R_TCP_FIN, 
	R_UDP, 
	R_ICMP, 
	R_MAXLIFE, 
	R_OVERBYTES, 
	R_OVERFLOWS, 
	R_FLUSH
};
#endif /* _MINIFLOWD_H */
