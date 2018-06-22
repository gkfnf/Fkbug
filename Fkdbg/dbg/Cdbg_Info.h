#pragma once
#include <windows.h>
#include <assert.h>
#define BEA_ENGINE_STATIC
#define BEA_USE_STDCALL
#include "BeaEngine_4.1/Win32/headers/BeaEngine.h"
#if _MSC_VER >1600  //VS2010
#pragma comment (lib,"legacy_stdio_definitions.lib") //FOR VS2015 
#endif

#ifndef _WIN64
#pragma comment(lib, "BeaEngine_4.1/Win32/Win32/Lib/BeaEngine.lib")
#pragma comment(linker, "/NODEFAULTLIB:\"crt.lib\"")
#else
#pragma comment(lib, "../BeaEngine_4.1/Win64/Win64/Lib/BeaEngine64.lib")
#pragma comment(linker, "/NODEFAULTLIB:\"crt64.lib\"")
#endif

#include "debugRegisters.h"


#define LOG(s) printf("%s %s %d\n",s,__FUNCTION__,__LINE__)

// 调试信息相关类
class Cdbg_Info
{
public:
	Cdbg_Info();
	~Cdbg_Info();

	// 输出调试相关信息
	void showDebugInfor(HANDLE hProc, HANDLE hThread, LPVOID address);
};

