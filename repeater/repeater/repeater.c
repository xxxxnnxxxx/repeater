#include "repeater.h"

#if (defined _WIN32)
# pragma warning(disable:4100)
# pragma warning(disable:4703)
# pragma warning(disable:4189)
#define WIN32_LEAN_AND_MEAN
# include <windows.h>
# include <pcap.h>
# include <eh.h>
#else
// Linux

#endif


#ifdef _WIN64
#  pragma comment(lib, "../lib/npcap/x64/Packet.lib")
#  pragma comment(lib, "../lib/npcap/x64/wpcap.lib")
#else
#  pragma comment(lib, "../lib/npcap/Packet.lib")
#  pragma comment(lib, "../lib/npcap/wpcap.lib")
#endif

#pragma comment(lib, "lua52")

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

int hexstr2bytes(const char* content, char *buf, int lenofbuf) {
	if (content == 0 || buf == 0 || lenofbuf == 0)
		return -1;

	char* result = (char*)buf;
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

// 检测函数调用参数个数是否正常
int CheckParamCount(lua_State* luaEnv, int paramCount)
{
	// lua_gettop获取栈中元素个数.  
	if (lua_gettop(luaEnv) != paramCount)
	{
		return SC_PARAMS;
	}

	return SC_SUCCESS;
}

static int RepeatPacket(lua_State* luaEnv) {
	const char* psInterfaceName = 0;
	const char* psPacket = 0;
	int ret = 0;

	// 检测参数个数是否正确.
	ret = CheckParamCount(luaEnv, 2);
	if (ret != SC_SUCCESS) {
		goto exit;
	}

	// 提取参数.  
	psInterfaceName = luaL_checkstring(luaEnv, 1);
	psPacket = luaL_checkstring(luaEnv, 2);

	ret = opendevice(psInterfaceName);
	if (ret != SC_SUCCESS) {
		goto exit;
	}

	char sendbuf[66000] = { 0 };
	ret = hexstr2bytes(psPacket, sendbuf, 66000);
	if (ret == -1) {
		goto exit;
	}

	ret = send_packet(sendbuf, ret);

exit:
	
	lua_pushinteger(luaEnv, ret);

	// 返回值个数为1个.  
	return 1;
}

static const struct luaL_Reg localLib[] = {
	{"RepeatPacket", RepeatPacket},
	{NULL, NULL}
};


int luaopen_repeater(lua_State* luaEnv) {
	luaL_newlib(luaEnv, localLib);
	return 1;
}