#ifndef _MINIFLOWD_H
#define _MINIFLOWD_H

#include <set>
#include <map>
#include <string>
#include <sstream>

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

#include <inttypes.h>
#include <pcap.h>

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
struct Flow 
{
	/* Flow identity (all are in network byte order) */
	int af;					/* Address family of flow */
	struct in_addr addr[2];			/* Endpoint addresses */
	uint16_t port[2];			/* Endpoint ports */
	uint8_t tcpFlags[2];			/* Cumulative OR of flags */
	uint8_t protocol;			/* Protocol */

	/* Per-flow statistics (all in _host_ byte order) */
	uint64_t flowSeq;			/* Flow ID */
	struct timeval flowStart;		/* Time of creation */
	struct timeval flowLast;		/* Time of last traffic */

	/* Per-endpoint statistics (all in _host_ byte order) */
	uint64_t octets[2];			/* Octets so far */
	uint64_t packets[2];			/* Packets so far */

        uint32_t expiresAt;                   /* time_t */
};
/*
 * Flow compare algrithom
 */
struct FlowCompare
{
	bool operator()(const struct Flow & left, const struct Flow & right) const
	{
		/* Be careful to avoid signed vs unsigned issues here */
	        if (left.expiresAt != right.expiresAt)
		{
        	        return (left.expiresAt > right.expiresAt);
		}

        	/* Make expiry entries unique by comparing flow sequence */
        	if (left.flowSeq != right.flowSeq)
		{
                	return (left.flowSeq > right.flowSeq);
		}
	
	}
};

/*
 * This structure is the root of the flow tracking system.
 * It holds the root of the tree of active flows and the head of the
 * tree of expiry events. It also collects miscellaneous statistics
 */
struct FlowTrack 
{
	/* The flows and their expiry events */
	std::map<std::string, struct Flow> flowsMap;	/* flow set */
	std::set<struct Flow, FlowCompare> expiriesSet;	/* expiries set */

	uint64_t nextFlowSeq;		/* Next flow ID */

	/* Flow timeouts */
	int tcpTimeout;			/* Open TCP connections */
	int tcpRstTimeout;		/* TCP flows after RST */
	int tcpFinTimeout;		/* TCP flows after bidi FIN */
	int udpTimeout;			/* UDP flows */
	int icmpTimeout;		/* ICMP flows */
	int generalTimeout;		/* Everything else */
	int maximumLifetime;		/* Maximum life for flows */
	int expiryInterval;		/* Interval between expiries */ 
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

/* Describes a datalink header and how to extract v4/v6 frames from it */
struct DataLinkType
{
	int datalinkType;	/* BPF datalink type */
	int skipLen;		/* Number of bytes to skip datalink header */
	int frameTypeOffset;	/* Datalink frametype offset */
	int frameTypeLen;	/* Datalink frametype length */
	int frameTypeBigEndian;	/* Set if frametype is big-endian */
	uint32_t frameTypeMask;	/* Mask applied to frametype */
	uint32_t frameTypeV4;	/* IPv4 frametype */
	uint32_t frameTypeV6;	/* IPv6 frametype */
};
#endif /* _MINIFLOWD_H */
