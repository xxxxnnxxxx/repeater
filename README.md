# WireShark发送数据插件

写这个插件的原因就是想重放接收到的数据包，但因为协议规则(比如说时间戳，建立连接后顺序号等）的问题，数据可以发送成功，但被请求端不一定给予返回。但为了补充wireshark缺少发送数据功能，也是准备把这篇文章补充上来。


首先我们开发的并不是二进制插件，而是基于lua和lua扩展实现的，发送数据包通过调用npcap的库。

# 一、开发准备

wireshark支持lua插件，我们要开发lua插件和lua扩展，我们就要知道wireshark用的是哪个lua版本，插件放在什么位置？

## 1. lua版本

如下图，我们打开wireshark程序，然后 `[帮助]`中`[关于wireshark]`。

![image](https://github.com/xxxxnnxxxx/repeater/blob/main/images/Wireshark%20lua版本.png)

图中显示wireshark使用的版本是: `Lua 5.2.4`, 那我们要开发扩展，就要下载相关的版本。

## 2. 下载和编译Lua

我们找到Lua的官方网站，找到相关的5.2.4版本的源代码：

官方网址：https://www.lua.org/versions.html#5.2

![image](https://github.com/xxxxnnxxxx/repeater/blob/main/images/lua5.2.4官方.png)

Lua5.2.4源码下载地址：https://www.lua.org/ftp/lua-5.2.4.tar.gz

在wireshark的程序目录中，我们看到了 `lua52.dll`, 那么我们也要编译一个lua的动态库，但我们只使用导出的lib就可以，真是使用的动态库就是wireshark程序目录中的库就可以了。

我们创建 `lua52` 的动态库工程，然后导入下载的 `lua5.2.4` 的源代码, 但要排除 `lua.c` 和 `luac.c` 因为这个是命令行相关的文件。然后在编译的时候定义 `LUA_BUILD_AS_DLL` 来生成动态库，如下图：

![image](https://github.com/xxxxnnxxxx/repeater/blob/main/images/lua源码1.png)

我们创建的工程如下图：

![image](https://github.com/xxxxnnxxxx/repeater/blob/main/images/lua%20dll.png)

## 3. npcap开发包

我们要发送数据，就要用到npcap开发包，本来wireshark已经安装了npcap， 但没有开发的SDK，那么我们就需要手动下载SDK。

npcap 官方网址：https://npcap.com/

如下图， 下载两个包：

![image](https://github.com/xxxxnnxxxx/repeater/blob/main/images/npcapsdk.png)

注意，我们需要再次安装一下npcap, 因为需要一些附加的dll, 如`wpcap.dll`, 我在开发工程中，发现这个总是找不到，如下图：(Npcap 1.78 installer)

![image](https://github.com/xxxxnnxxxx/repeater/blob/main/images/npcapinstaller.png)

选中图中的两个选项。

下载好的SDK，我们在后面创建扩展的时候使用。


# 二、Lua扩展库开发

## 1. lua 扩展库

lua扩展库要符合以下几点：

1. 导出函数以 `luaopen_` 开头，后面的库的名称

2. 导出函数 `luaopen_xxxx` 其实 `xxxx` 必须和动态库一样的名称

3. 在导出函数中，注册使用的函数列表，如下：

    ![image](https://github.com/xxxxnnxxxx/repeater/blob/main/images/repeatproject1.png)

4. 导出函数和注册的调用函数都使用参数 `lua_State *` 作为参数， 代码如下：

    ```c
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
    ```

## 2. npcap 库

因为我们要使用npcap库发送数据包，那么我就要引入npcap sdk, 在这个工程中，我直接放在解决方案的同样的目录中，如下图：

![image](https://github.com/xxxxnnxxxx/repeater/blob/main/images/npcaplib1.png)
![image](https://github.com/xxxxnnxxxx/repeater/blob/main/images/npcaplib2.png)
![image](https://github.com/xxxxnnxxxx/repeater/blob/main/images/npcaplib3.png)

在我们的工程中引入包含目录：

![image](https://github.com/xxxxnnxxxx/repeater/blob/main/images/npcaplib4.png)

## 3. 引入库

我们需要引入lua和npcap相关的头文件和lib库，代码如下：

```c
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
```

## 4. 代码注解1(npcap库发送数据)

### 1. `int opendevice(const char* devicename)` 打开网络接口

代码如下：

```c
// 传入的参数为网络接口的名称，但注意在windows下不是ipconfig下获取的接口名称
// 而是设备的符号连接，例如：\Device\NPF_Loopback
int opendevice(const char* devicename) {
	char errbuf[PCAP_ERRBUF_SIZE + 1] = { 0 };
	int ret = SC_SUCCESS;

	if (fp != 0) {
		return SC_SUCCESS;
	}
    // 创建一个pcap设备，并返回pcap_t*的一个句柄
	fp = pcap_create(devicename, errbuf);
	if (fp == NULL) {
		ret = SC_NOOPENDEVICE;
		goto exit;
	}
    // 下面是设备的设置
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
    // 想要使用这个设备发送数据，那么必须要设置为活动，这样才能启动设备
	ret = pcap_activate(fp);
	if (ret < 0) {
		ret = SC_SETPCAPFAILED;
		goto exit;
	}

exit:

	return ret;
}
```

### 2. `int send_packet(const u_char* content, size_t size)` 发送数据

代码如下：

```c
// 把要发送的缓冲区和长度作为参数传递
int send_packet(const u_char* content, size_t size) {
	int ret = SC_SUCCESS;
	if (fp == 0)
		return SC_NOOPENDEVICE;

	if (content == 0 || size == 0)
		return SC_PARAMS;
    // 这个就是pcap的发送数据函数
	ret = pcap_sendpacket(fp, content, (int)size);
	if (ret == 0) {
		ret = SC_SUCCESS;
	}
	else {
		ret = SC_SENDFAILD;
	}

	return ret;
}
```

### 3. `static int RepeatPacket(lua_State* luaEnv)` lua扩展的发送数据函数

代码如下：

```c
// 参数就是按规定的 lua_State 指针
// lua扩展，返回的整数就是返回给lua脚本的参数个数
// 我们给这个函数传递的参数是网络接口名称和要发送的数据
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
    // tcp相关包的最大长度65535，加上固定的头部长度，660000足够保存数据了
	char sendbuf[66000] = { 0 };
    // hexstr2bytes 主要把lua脚本传递的字符串转化成字节数组，然后发送出去
	ret = hexstr2bytes(psPacket, sendbuf, 66000);
	if (ret == -1) {
		goto exit;
	}

	ret = send_packet(sendbuf, ret);

exit:
	// 把返回的结果压入luaEnv中，lua脚本就可以获取返回值了
	lua_pushinteger(luaEnv, ret);

	// 返回值个数为1个.  
	return 1;
}
```

### 4. lua 定义导出列表

代码如下：

```c
// luaL_Reg固定结构
// 第一个结构成员为函数名称
// 第二个结构成员为函数地址
static const struct luaL_Reg localLib[] = {
	{"RepeatPacket", RepeatPacket},
	{NULL, NULL}
};
```

# 三、lua 脚本插件开发

lua扩展我们已经介绍完了，那么就是lua脚本的部分了，在这里比较简单，我们先看代码：

```lua
-- Define the menu entry's callback
local function dialog_menu(fieldinfo)
  local repeater = require("repeater")
  -- 数据包
  local datapacket = fieldinfo.range:bytes():tohex(false, ' ')
  -- 得到所打开的网络接口名称
  local pattern = "on interface%s*(.-)%s*, id"
  local interfaceName = string.match(fieldinfo.display, pattern)
  -- 显示对话框
  local win = TextWindow.new("Repeater");
  win:set_editable(true)
  -- add button to change text to uppercase
  win:add_button("Repeat", function()
          local text = win:get_text()
          if text ~= "" then
                  local ret = repeater.RepeatPacket(interfaceName, text)
                  if ret == 0 then
                    print("send successfully")
                  else
                    print("send failed")
                  end 
          end
  end)

  win:set(datapacket)
  
end

-- Notify the user that the menu was created
if gui_enabled() then
  register_packet_menu("Repeat Packet",dialog_menu, "ip")
end
```

1. `gui_enabled()` 是判断是否有gui页面，因为wireshark可以命令行下使用，所以这个地方要判断。

2. `register_packet_menu("Repeat Packet",dialog_menu, "ip")` 注册右键菜单，当右键选中包列表的时候，显示这个菜单，第一个参数是菜单名称，第二个是处理函数， 第三个`ip`就是对ip协议的包才显示菜单。

3. `local function dialog_menu(fieldinfo)` 这个函数就是菜单处理函数，只有一个参数 `FieldInfo` 结构，这个后面我们会把wireshark的文档放在引用中，可以查看具体的内容和处理。

4. `local datapacket = fieldinfo.range:bytes():tohex(false, ' ')` 这个地方就是通过fieldinfo得到当前选中的数据包内容，转化为十六进制字符串，格式如：`1A 8F C3 B6 94 41 61 C7 E8 D0`

5. 获取网络接口名称

    ```lua
    local pattern = "on interface%s*(.-)%s*, id"
    local interfaceName = string.match(fieldinfo.display, pattern)
    ```
    因为我在这个地方查看文档，并没有找到直接获取网络接口的函数，但通过fieldinfo.display中，包含接口字符串，所以在这个地方，我们通过正则匹配到接口名称，这个display字符串在真正开发的过程中可以自行查看到。

6. 显示对话框，添加发送按钮

    ```lua
    local win = TextWindow.new("Repeater");
    win:set_editable(true)
    -- add button to send packet
    win:add_button("Repeat", function()
            local text = win:get_text()
            if text ~= "" then
                    local ret = repeater.RepeatPacket(interfaceName, text)
                    if ret == 0 then
                        print("send successfully")
                    else
                        print("send failed")
                    end 
            end
    end)
    ```

# 四、配置使用插件

插件分为两个部分， 一个是扩展库，一个是lua脚本，扩展库可以直接放入到wireshark程序所在目录就可以， 然后在 lua 脚本中 `local repeater = require("repeater")` 引用就可以了。那么lua脚本放在什么地方呢？我们可以在wireshark的帮助菜单的关于wireshark中找到，如下图： 

![image](https://github.com/xxxxnnxxxx/repeater/blob/main/images/luapluginpos.png)

扩展库的位置：

![image](https://github.com/xxxxnnxxxx/repeater/blob/main/images/lualibpos.png)

注意：脚本插件的文件名称不能和扩展动态库的名称相同，要不引用的时候造成错误。


# 五、运行

所有的工作都完成了，运行效果如下图：

![image](https://github.com/xxxxnnxxxx/repeater/blob/main/images/run1.png)

![image](https://github.com/xxxxnnxxxx/repeater/blob/main/images/run2.png)

# 六、参考

1. 记录 Wireshark lua 5.2.4 插件 调用 C/C++ DLL 动态库 的心得 ：https://blog.csdn.net/YiNST/article/details/123877801

2. Chapter 11. Wireshark’s Lua API Reference Manual : https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html