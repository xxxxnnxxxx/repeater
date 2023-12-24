// sendpacket.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <iostream>

# pragma warning(disable:4100)
# pragma warning(disable:4703)
# pragma warning(disable:4189)
#define WIN32_LEAN_AND_MEAN
# include <windows.h>
# include <pcap.h>
# include <eh.h>

#  pragma comment(lib, "../lib/npcap/x64/Packet.lib")
#  pragma comment(lib, "../lib/npcap/x64/wpcap.lib")

#define SC_SUCCESS 0
#define SC_PARAMS		 0x70000001		// 参数错误
#define SC_NOOPENDEVICE  0x70000002		// 没有打开设备
#define SC_SETPCAPFAILED 0x70000003
#define SC_SENDFAILD	 0x70000004		// 发送失败

pcap_t* fp;


int opendevice(const char* devicename) {
	char errbuf[PCAP_ERRBUF_SIZE + 1] = { 0 };
	int ret = SC_SUCCESS;

	if (fp != 0) {
		return SC_SUCCESS;
	}

	fp = pcap_create(devicename, errbuf);
	if (fp == NULL) {
		ret = SC_NOOPENDEVICE;
		goto exit;
	}
	/*
	ret = pcap_set_snaplen(fp, 65536);
	if (ret < 0) {
		ret = SC_SETPCAPFAILED;
		goto exit;
	}
	ret = pcap_set_promisc(fp, 1);
	if (ret < 0) {
		ret = SC_SETPCAPFAILED;
		goto exit;
	}
	ret = pcap_set_timeout(fp, 1000);
	if (ret < 0) {
		ret = SC_SETPCAPFAILED;
		goto exit;
	}
*/
	ret = pcap_activate(fp);
	if (ret < 0) {
		ret = SC_SETPCAPFAILED;
		goto exit;
	}

exit:

	return ret;
}

void closedevice() {
	if (fp) {
		pcap_close(fp);
		fp = 0;
	}
}

// send data package
int send_packet(const u_char* content, size_t size) {
	int ret = SC_SUCCESS;
	if (fp == 0)
		return SC_NOOPENDEVICE;

	if (content == 0 || size == 0)
		return SC_PARAMS;

	ret = pcap_sendpacket(fp, content, (int)size);
	if (ret == 0) {
		ret = SC_SUCCESS;
	}
	else {
		ret = SC_SENDFAILD;
	}

	return ret;
}

int hexstr2bytes(const char* content, u_char* buf, int lenofbuf) {
	if (content == 0 || buf == 0 || lenofbuf == 0)
		return -1;

	u_char* result = buf;
	const char* p = content;
	int i = 0;
	while (1) {
		int cursor;
	p1:
		cursor = 1;
		if (p == content + strlen(content)) break;
	p2:
		if (*p <= '9' && *p >= '0') {
			result[i] += (*p - 0x30) << (cursor * 4);
			cursor--;
		}
		else if (*p <= 'F' && *p >= 'A') {
			result[i] += (*p - 0x41 + 10) << (cursor * 4);
			cursor--;
		}
		else if (*p <= 'f' && *p >= 'a') {
			result[i] += (*p - 0x61 + 10) << (cursor * 4);
			cursor--;
		}

		if (cursor == 1) {
			p++;
			goto p1;
		}
		else if (cursor == 0) {
			p++;
			goto p2;
		}
		else if (cursor == -1) {
			p++;
			i++;
			goto p1;
		}
	}

	return i;
}

int main()
{
	const char* data = "D8 A8 C8 8E 00 D8 84 5C F3 4F 19 83 08 00 45 00 00 3C 19 C3 00 00 80 01 00 00 C0 A8 01 05 2C E4 F9 03 08 00 46 7B 00 01 06 E0 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 61 62 63 64 65 66 67 68 69";
	const char* interfaceName = "\\Device\\NPF_{D50F087F-49E2-4423-B22F-DA7F46D42394}";

	int ret = opendevice(interfaceName);

	u_char sendbuf[66000] = { 0 };
	ret = hexstr2bytes(data, sendbuf, 66000);
	if (ret == -1) {
		MessageBoxA(NULL, "2", "repeater", MB_OK);
		return -1;
	}

	ret = send_packet(sendbuf, ret);
}
