#ifndef _MINIFLOWD_H
#define _MINIFLOWD_H

#include <list>
#include <set>
#include <string>
#include <sstream>
#include <iostream>

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

#define __STDC_FORMAT_MACROS 
#include <inttypes.h>
#include <pcap.h>


/*
 * Capture length for libpcap: Must fit the link layer header, plus 
 * a maximally sized ipv4 header and most of a TCP header
 */
#define LIBPCAP_SNAPLEN_V4	96


/*
 * Timeouts, minimal value is 1, do not use 0
 */
#define DEFAULT_TCP_TIMEOUT		3600
#define DEFAULT_TCP_RST_TIMEOUT		5
#define DEFAULT_TCP_FIN_TIMEOUT		5
#define DEFAULT_UDP_TIMEOUT		300
#define DEFAULT_ICMP_TIMEOUT		60
#define DEFAULT_GENERAL_TIMEOUT		3600
#define DEFAULT_MAXIMUM_LIFETIME	(3600*24*7)
#define DEFAULT_EXPIRY_INTERVAL		60

//expire reason
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
	Flow()
	{
		af = 0;
		memset(addr, 0, sizeof(addr));
		memset(port, 0, sizeof(port));
		memset(tcpRst, 0, sizeof(tcpRst));
		memset(tcpFin, 0, sizeof(tcpFin));
		protocol = 0;
		flowSeq = 0;
		memset(&flowStart, 0, sizeof(flowStart));
		memset(&flowLast, 0, sizeof(flowLast));
		memset(octets, 0, sizeof(octets));
		memset(packets, 0, sizeof(packets));
		expiresAt = 3600;
	}
	/* Flow identity (all are in network byte order) */
	int af;					/* Address family of flow */
	struct in_addr addr[2];			/* Endpoint addresses */
	uint16_t port[2];			/* Endpoint ports */
	uint8_t tcpRst[2];				/* tcp flags has rst */
	uint8_t tcpFin[2];				/* tcp flags has fin*/
	uint8_t protocol;			/* Protocol */

	/* Per-flow statistics (all in _host_ byte order) */
	uint64_t flowSeq;			/* Flow ID */
	struct timeval flowStart;		/* Time of creation */
	struct timeval flowLast;		/* Time of last traffic */

	/* Per-endpoint statistics (all in _host_ byte order) */
	uint64_t octets[2];			/* Octets so far */
	uint64_t packets[2];			/* Packets so far */

        uint32_t expiresAt;          	         /* time_t */
	REASON   reason;			 /*Expire reason*/

	bool operator==( const Flow &other ) const
    	{
        	if (this->af != other.af)
		{
                	return false;
		}

		if (memcmp(&(this->addr[0]), &(other.addr[0]), sizeof(this->addr[0])) != 0)
		{
			return false;
		}

		if (memcmp(&(this->addr[1]), &(other.addr[1]), sizeof(this->addr[1])) != 0)
		{
			return false;
		}

        	if (this->protocol != other.protocol)
		{
			return false;
		}
		
		if (this->port[0] != other.port[0])
		{
			return false;
		}

        	if (this->port[1] != other.port[1])
		{
			return false;
		}

		return true;
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
	std::list<Flow> flowsList;	/* flow list */

	uint64_t nextFlowSeq;		/* Next flow ID */
	int      linkType;		/* Data link type */
};


/* Describes a datalink header and how to extract v4/v6 frames from it */
struct DataLinkType
{
	int dataLinkType;	/* BPF datalink type */
	int skipLen;		/* Number of bytes to skip datalink header */
	int frameTypeOffset;	/* Datalink frametype offset */
	int frameTypeLen;	/* Datalink frametype length */
	int frameTypeBigEndian;	/* Set if frametype is big-endian */
	uint32_t frameTypeMask;	/* Mask applied to frametype */
	uint32_t frameTypeV4;	/* IPv4 frametype */
	uint32_t frameTypeV6;	/* IPv6 frametype */
};
#endif /* _MINIFLOWD_H */
