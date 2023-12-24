#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

typedef unsigned char u_char;
typedef unsigned char u_int8;
typedef unsigned short u_short;
typedef unsigned int u_int32;
typedef unsigned __int64 u_int64;

#pragma pack(1)
//��̫������ͷ
struct eth_header {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;  //�����һ��ΪIPЭ�顣��ether_type��ֵ����0x0800
};

// ip header (little endian)
struct _ip_header_v4 {
	u_char ihl : 4;			// ihl (�ײ�����)
	u_char version : 4;		// version

	u_char tos;				// 8 λ��������
	u_short total_length;	// �ܳ���
	u_short identification;		// 16λ��ʶ
	u_char ip_frag_offset : 5;        // Fragment offset field

	u_char  ip_more_fragment : 1;
	u_char  ip_dont_fragment : 1;
	u_char  ip_reserved_zero : 1;

	unsigned char  ip_frag_offset1;    //fragment offset
	u_char ttl;				// 8λ����ʱ��
	u_char protocol;		// 8λЭ��
	u_short checksum;		// 16λ�ײ�У���
	u_int32 srcip;			// 32λԴIP
	u_int32 dstip;			// 32λĿ��IP
};

// tcp header (little endian)
struct _tcp_header {
	u_short srcport;			// 16λԴ�˿ں�
	u_short dstport;			// 16λĿ�Ķ˿ں�
	u_int32 sequence_number;	// 32λ���к�
	u_int32 ack_number;			// 32λȷ�����к�
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

	u_short window;		// ���ڴ�С
	u_short checksum;		// 16λУ���
	u_short urgentpointer;	// 16λ����ָ��
};

#pragma push()

#endif
