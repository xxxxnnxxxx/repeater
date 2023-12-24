#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

typedef unsigned char u_char;
typedef unsigned char u_int8;
typedef unsigned short u_short;
typedef unsigned int u_int32;
typedef unsigned __int64 u_int64;

#pragma pack(1)
//以太网数据头
struct eth_header {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;  //如果上一层为IP协议。则ether_type的值就是0x0800
};

// ip header (little endian)
struct _ip_header_v4 {
	u_char ihl : 4;			// ihl (首部长度)
	u_char version : 4;		// version

	u_char tos;				// 8 位服务类型
	u_short total_length;	// 总长度
	u_short identification;		// 16位标识
	u_char ip_frag_offset : 5;        // Fragment offset field

	u_char  ip_more_fragment : 1;
	u_char  ip_dont_fragment : 1;
	u_char  ip_reserved_zero : 1;

	unsigned char  ip_frag_offset1;    //fragment offset
	u_char ttl;				// 8位生存时间
	u_char protocol;		// 8位协议
	u_short checksum;		// 16位首部校验和
	u_int32 srcip;			// 32位源IP
	u_int32 dstip;			// 32位目的IP
};

// tcp header (little endian)
struct _tcp_header {
	u_short srcport;			// 16位源端口号
	u_short dstport;			// 16位目的端口号
	u_int32 sequence_number;	// 32位序列号
	u_int32 ack_number;			// 32位确认序列号
	u_char	res1 : 4;
	u_char doff : 4;
	union {
		u_char signal;
		struct {
			u_char	fin : 1;
			u_char	syn : 1;
			u_char	rst : 1;
			u_char	psh : 1;
			u_char	ack : 1;
			u_char	urg : 1;
			u_char	res2 : 2;
		};

	};

	u_short window;		// 窗口大小
	u_short checksum;		// 16位校验和
	u_short urgentpointer;	// 16位紧急指针
};

#pragma push()

#endif
