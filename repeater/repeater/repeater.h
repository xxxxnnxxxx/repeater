#ifndef _REPEATER_H_
#define _REPEATER_H_

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#ifdef __cplusplus
#	ifdef ARP_EXPORTS
#		define ARPAPI extern "C" __declspec(dllexport)
#	else
#		define ARPAPI extern "C"  __declspec(dllimport) 
#	endif
#else
#	ifdef REPEATER_EXPORTS
#		define ARPAPI  __declspec(dllexport)
#	else
#		define ARPAPI  __declspec(dllimport) 
#	endif
#endif




ARPAPI int luaopen_repeater(lua_State* luaEnv);


#endif