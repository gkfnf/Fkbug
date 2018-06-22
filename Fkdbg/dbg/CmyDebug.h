#pragma once
#include "Cdbg_Info.h"
#include "Cbp_About.h"
#include <DbgHelp.h>
#include <winnt.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <atlstr.h>

#pragma  comment (lib, "Dbghelp.lib")


#define F_BLUE     FOREGROUND_BLUE					// 深蓝
#define F_H_BLUE   0x0001|0x0008						// 亮蓝
#define F_GREEN    0x0002										// 深绿
#define F_H_GREEN  0x0002|0x0008						// 亮绿
#define F_RED      0x0004										// 深红
#define F_H_RED    0x0004|0x0008						// 亮红
#define F_YELLOW   0x0002|0x0004					  // 深黄
#define F_H_YELLOW 0x0002|0x0004|0x0008	    // 亮黄
#define F_PURPLE   0x0001|0x0004						// 深紫
#define F_H_PURPLE 0x0001|0x0004|0x0008			// 亮紫
#define F_CYAN     0x0002|0x0004						// 深青
#define F_H_CYAN   0x0002|0x0006|0x0008			// 亮青
#define F_WHITE    0x0004|0x0002|0x0001
#define F_H_WHITE  0x0004|0x0002|0x0001|0x0008
#define F_TEST     0x0007|0x000b|0x0003



// 调试器主体
class CmyDebug
{
public:
	CmyDebug();
	~CmyDebug();

	void CreateDebug();
	void EnterDebugLoop();
	

private:
	DWORD OnExceptionDebugEvent(DEBUG_EVENT dbgEv);
	DWORD OnExceptionINT3(EXCEPTION_RECORD& record);
	DWORD OnExceptionSingleStep(EXCEPTION_RECORD& record);
	DWORD OnExceptionMem(DEBUG_EVENT& Exception);

	

	void   userInput(EXCEPTION_RECORD& record);

	void   showDisasm(HANDLE hProc, LPVOID address, int nLen);
	void   ShowRegister();
	void   ShowStack();
	SIZE_T GetSymFuncName(SIZE_T Address, CString& strName);
	void   WriteChar(int x, int y, char* pszChar, int _number, WORD nColor);



	void   TraverseModule(DWORD PID);
	void   Dump(char* Name, char* path);


	SIZE_T ModuleToAddr(TCHAR* _Name, DWORD _PID);
	void   PaserExportTable(SIZE_T Address);
	void   PaserImportTable(SIZE_T Address);

	//SIZE_T FindApiAddr(HANDLE hProcess)
private:
	Cbp_About m_bpAbout;
	Cdbg_Info m_dbgInfo;

	HANDLE m_process;
	HANDLE m_Thread;


	HANDLE m_hfile;
	DWORD  m_Size;
	BYTE*  m_pBuff;
	char   m_path[MAX_PATH];


	DWORD  m_processID;
	

	bool   m_MemStep;                // 谁引起的单步的标志
	bool   m_ConditionStep;
	bool   m_Oep;

        
};

