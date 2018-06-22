// Shell.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "Shell.h"
#include "resource.h"


#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")
//#pragma comment(linker,"/entry:main")

//函数和变量的声明
DWORD MyGetProcAddress();		//自定义GetProcAddress

//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR szCmdLine, int iCmdShow);

//LRESULT CALLBACK PSWWCndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

void PswBox();
HMODULE	GetKernel32Addr();		// 获取Kernel32加载基址
void Start();					// 启动函数(Shell部分的入口函数)
void InitFun();					// 初始化函数指针和变量
void DeXorCode();				// 解密操作
void RecReloc();				// 修复重定位操作
void RecIAT();					// 修复IAT操作
void DecryptIAT();				// 解密IAT
void DeXorMachineCode();		// 机器码绑定解密
void _stdcall FusedFunc(DWORD funcAddress);      // 混淆
void CallTLS();                 // 调用 TLS 回调



SHELL_DATA g_stcShellData = { (DWORD)Start };
DWORD dwPEOEP = 0;				//壳用到的全局变量结构体
DWORD dwImageBase	= 0;		//整个程序的镜像基址
DWORD dwTemp1;
DWORD dwTemp2;
DWORD dwTemp3;
PDWORD g_pTRUEIAT = NULL;

//  Shell部分用到的函数定义
fnGetProcAddress	g_pfnGetProcAddress		= NULL;
fnLoadLibraryA		g_pfnLoadLibraryA		= NULL;
fnGetModuleHandleA	g_pfnGetModuleHandleA	= NULL;
fnVirtualProtect	g_pfnVirtualProtect		= NULL;
fnVirtualAlloc		g_pfnVirtualAlloc		= NULL;
fnExitProcess		g_pfnExitProcess		= NULL;

/*  修复 IAT 后其实不用再动态获取 API 了  
fnRegisterClassW    g_pfnRegisterClassW		= NULL;
fnCreateWindowExW   g_pfnCreateWindowExW	= NULL;
fnGetMessageW       g_pfnGetMessageW		= NULL;
fnTranslateMessage  g_pfnTranslateMessage	= NULL;
fnDispatchMessage   g_pfnDispatchMessage	= NULL;
fnUpdateWidow		g_pfnUpdateWindow		= NULL;
fnShowWindow		g_pfnShowWindow			= NULL;
//fnGetStockObject    g_pfnGetStockObject		= NULL;
fnDefWindowProcW    g_pfnDefWindowProcW		= NULL;
fnGetWindowText     g_pfnGetWindowText		= NULL;
fnMessageBoxW       g_pfnMessageBoxW		= NULL;
fnPostQuitMessage   g_pfnPostQuitMessage	= NULL;
*/
HINSTANCE hInst;
bool key = TRUE;

void Start()
{
	//初始化用到的函数
	InitFun();

	//显示MessageBox
	if (g_stcShellData.bSelect[4] == TRUE)
	{
		
		//WinMain(LoadLibrary(L"Shell.dll"), NULL, NULL, NULL);
		PswBox();
		//g_pfnMessageBoxA(0, "欢迎使用 CyxvcProtect !", "Hello!", 0);
	}

	//机器码绑定
	if (g_stcShellData.bSelect[2] == TRUE)
		DeXorMachineCode();

	//解密代码段
	if (g_stcShellData.bSelect[0] == TRUE)
		DeXorCode();
	
	//修复重定位
	if (g_stcShellData.stcPERelocDir.VirtualAddress)
		RecReloc();

	//修复IAT
	if (g_stcShellData.bSelect[1] == TRUE)
	{
		DWORD dwOldProtect = 0;
		g_pfnVirtualProtect(
			(LPBYTE)(dwImageBase + g_stcShellData.dwIATSectionBase), g_stcShellData.dwIATSectionSize,
			PAGE_EXECUTE_READWRITE, &dwOldProtect);

		PDWORD pIndex = (PDWORD)g_pfnVirtualAlloc(0, g_stcShellData.dwNumOfIATFuns*sizeof(DWORD),
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		//如果有IAT加密，则对IAT进行解密
		DecryptIAT();
		//填充IAT(第一遍)
		for (DWORD i = 0; i < g_stcShellData.dwNumOfIATFuns; i += dwTemp1)
		{
			pIndex[i] = g_stcShellData.dwSizeOfModBuf^g_stcShellData.dwSizeOfFunBuf;
			*(DWORD*)((DWORD)g_stcShellData.pMyImport[i].m_dwIATAddr + dwImageBase) = g_pTRUEIAT[i];
		}

		//第二遍
		for (DWORD i = 0; i < g_stcShellData.dwNumOfIATFuns; i += dwTemp2)
		{
			*(DWORD*)((DWORD)g_stcShellData.pMyImport[i].m_dwIATAddr + dwImageBase) = g_pTRUEIAT[i];
			pIndex[i] = g_stcShellData.dwSizeOfModBuf^g_stcShellData.dwSizeOfFunBuf;
		}

		//第三遍
		for (DWORD i = 0; i < g_stcShellData.dwNumOfIATFuns; i += dwTemp3)
		{
			*(DWORD*)((DWORD)g_stcShellData.pMyImport[i].m_dwIATAddr + dwImageBase) = g_pTRUEIAT[i];
			pIndex[i] = g_stcShellData.dwSizeOfModBuf^g_stcShellData.dwSizeOfFunBuf;
		}

		//第四遍
		for (DWORD i = 0; i < g_stcShellData.dwNumOfIATFuns; i++)
		{
			if (pIndex[i] != (g_stcShellData.dwSizeOfModBuf^g_stcShellData.dwSizeOfFunBuf))
			{
				*(DWORD*)((DWORD)g_stcShellData.pMyImport[i].m_dwIATAddr + dwImageBase) = g_pTRUEIAT[i];
			}
		}
	}
	else
	{
		//如果没有IAT加密，则正常修复IAT
		RecIAT();
	}

	//FusedFunc((DWORD)CallTLS);

	//获取OEP信息
	dwPEOEP = g_stcShellData.dwPEOEP + dwImageBase;

	_asm {
		mov eax, eax;
		mov eax, eax;
		mov eax, eax;
		mov eax, eax;
		mov eax, eax;
	}
	FusedFunc(dwPEOEP);
	__asm
	{
		pop edi
		pop esi
		pop ebx
 		push dwPEOEP
 		ret
	}

	g_pfnExitProcess(0);	//实际不会执行此条指令
}


// 函数说明:	修复 IAT
void RecIAT()
{
	//1.获取导入表结构体指针
	PIMAGE_IMPORT_DESCRIPTOR pPEImport = 
		(PIMAGE_IMPORT_DESCRIPTOR)(dwImageBase + g_stcShellData.stcPEImportDir.VirtualAddress);
	
	//2.修改内存属性为可写
	DWORD dwOldProtect = 0;
	g_pfnVirtualProtect(
		(LPBYTE)(dwImageBase + g_stcShellData.dwIATSectionBase), g_stcShellData.dwIATSectionSize,
		PAGE_EXECUTE_READWRITE, &dwOldProtect);

	//3.开始修复IAT
	while (pPEImport->Name)
	{
		//获取模块名
		DWORD dwModNameRVA = pPEImport->Name;
		char* pModName = (char*)(dwImageBase + dwModNameRVA);
		HMODULE hMod = g_pfnLoadLibraryA(pModName);

		//获取IAT信息(有些文件INT是空的，最好用IAT解析，也可两个都解析作对比)
		PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)(dwImageBase + pPEImport->FirstThunk);
		
		//获取INT信息(同IAT一样，可将INT看作是IAT的一个备份)
		//PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)(dwImageBase + pPEImport->OriginalFirstThunk);

		//通过IAT循环获取该模块下的所有函数信息(这里之获取了函数名)
		while (pIAT->u1.AddressOfData)
		{
			//判断是输出函数名还是序号
			if (IMAGE_SNAP_BY_ORDINAL(pIAT->u1.Ordinal))
			{
				//输出序号
				DWORD dwFunOrdinal = (pIAT->u1.Ordinal) & 0x7FFFFFFF;
				DWORD dwFunAddr = g_pfnGetProcAddress(hMod, (char*)dwFunOrdinal);
				*(DWORD*)pIAT = (DWORD)dwFunAddr;
			}
			else
			{
				//输出函数名
				DWORD dwFunNameRVA = pIAT->u1.AddressOfData;
				PIMAGE_IMPORT_BY_NAME pstcFunName = (PIMAGE_IMPORT_BY_NAME)(dwImageBase + dwFunNameRVA);
				DWORD dwFunAddr = g_pfnGetProcAddress(hMod, pstcFunName->Name);
				*(DWORD*)pIAT = (DWORD)dwFunAddr;
			}
			pIAT++;
		}
		//遍历下一个模块
		pPEImport++;
	}

	//4.恢复内存属性
	g_pfnVirtualProtect(
		(LPBYTE)(dwImageBase + g_stcShellData.dwIATSectionBase), g_stcShellData.dwIATSectionSize,
		dwOldProtect, &dwOldProtect);
}


// 函数说明:	解密IAT
void DecryptIAT()
{
	//初始化指针信息
	g_stcShellData.pMyImport = (PMYIMPORT)((DWORD)dwImageBase + g_stcShellData.dwIATBaseRVA);
	g_stcShellData.pModNameBuf = (CHAR*)g_stcShellData.pMyImport + g_stcShellData.dwNumOfIATFuns*sizeof(MYIMPORT);
	g_stcShellData.pFunNameBuf = (CHAR*)g_stcShellData.pModNameBuf + g_stcShellData.dwSizeOfModBuf;

	//设置内存属性
// 	DWORD dwOldProtect = 0;
// 	g_pfnVirtualProtect(
// 		(LPBYTE)(dwImageBase + g_stcShellData.dwIATSectionBase), g_stcShellData.dwIATSectionSize,
// 		PAGE_EXECUTE_READWRITE, &dwOldProtect);

	//解密模块名
	for (DWORD i = 0; i < g_stcShellData.dwSizeOfModBuf; i++)
	{
		if (((char*)g_stcShellData.pModNameBuf)[i] != 0)
		{
			((char*)g_stcShellData.pModNameBuf)[i] ^= g_stcShellData.dwXorKey;
		}
	}

	//开始解密
	for (DWORD i = 0; i < g_stcShellData.dwNumOfIATFuns; i++)
	{
		if (g_stcShellData.pMyImport[i].m_bIsOrdinal)
		{
			//序号导出函数
			HMODULE hMod = NULL; 
			char* pModName = (char*)g_stcShellData.pModNameBuf + g_stcShellData.pMyImport[i].m_dwModNameRVA;
			hMod = g_pfnGetModuleHandleA(pModName);
			if (hMod == NULL)
			{
				hMod = g_pfnLoadLibraryA(pModName);
			}
			
			DWORD dwFunOrdinal = g_stcShellData.pMyImport[i].m_Ordinal;
			DWORD dwFunAddr = g_pfnGetProcAddress(hMod, (char*)dwFunOrdinal);
			//*(DWORD*)((DWORD)g_stcShellData.pMyImport[i].m_dwIATAddr + dwImageBase) = (DWORD)dwFunAddr;

			//薛老师的加密
			BYTE byByte[] {
				0xe8, 0x01, 0x00, 0x00, 0x00, 0xe9, 0x58, 0xeb, 0x01, 0xe8, 0xb8, 0x11, 0x11, 0x11, 0x11, 0xeb,
					0x01, 0x15, 0x35, 0x15, 0x15, 0x15, 0x15, 0xeb, 0x01, 0xff, 0x50, 0xeb, 0x02, 0xff, 0x15, 0xc3};
			PDWORD pAddr = (PDWORD)&(byByte[11]);
			*pAddr = dwFunAddr ^ 0x15151515;
			PBYTE pNewAddr = (PBYTE)g_pfnVirtualAlloc(0, sizeof(byByte), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			memcpy(pNewAddr, byByte, sizeof(byByte));
			g_pTRUEIAT[i] = (DWORD)pNewAddr;
		}
		else
		{
			//函数名导出函数
			HMODULE hMod = NULL;
			char* pModName = (char*)g_stcShellData.pModNameBuf + g_stcShellData.pMyImport[i].m_dwModNameRVA;
			hMod = g_pfnGetModuleHandleA(pModName);
			if (hMod == NULL)
			{
				hMod = g_pfnLoadLibraryA(pModName);
			}

			//解密IAT函数名
			DWORD dwFunNameRVA = g_stcShellData.pMyImport[i].m_dwFunNameRVA;
			char* pFunName = (char*)g_stcShellData.pFunNameBuf + dwFunNameRVA;
			DWORD j = 0;
			while (pFunName[j])
			{
				((char*)pFunName)[j] ^= g_stcShellData.dwXorKey;
				j++;
			}

			DWORD dwFunAddr = g_pfnGetProcAddress(hMod, pFunName);
			//*(DWORD*)((DWORD)g_stcShellData.pMyImport[i].m_dwIATAddr + dwImageBase) = (DWORD)dwFunAddr;

			//薛老师的加密
			BYTE byByte[] {
				0xe8, 0x01, 0x00, 0x00, 0x00, 0xe9, 0x58, 0xeb, 0x01, 0xe8, 0xb8, 0x11, 0x11, 0x11, 0x11, 0xeb,
					0x01, 0x15, 0x35, 0x15, 0x15, 0x15, 0x15, 0xeb, 0x01, 0xff, 0x50, 0xeb, 0x02, 0xff, 0x15, 0xc3};
			PDWORD pAddr = (PDWORD)&(byByte[11]);
			*pAddr = dwFunAddr ^ 0x15151515;
			PBYTE pNewAddr = (PBYTE)g_pfnVirtualAlloc(0, sizeof(byByte), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			memcpy(pNewAddr, byByte, sizeof(byByte));
			g_pTRUEIAT[i] = (DWORD)pNewAddr;

			//抹去IAT函数名
			while (pFunName[j-1])
			{
				pFunName[j - 1] = 0;
				j--;
			}
		}
	}
	//抹去模块名
	for (DWORD i = 0; i < g_stcShellData.dwSizeOfModBuf; i++)
	{
		((char*)g_stcShellData.pModNameBuf)[i] = 0;
	}

	//恢复内存属性
// 	g_pfnVirtualProtect(
// 		(LPBYTE)(dwImageBase + g_stcShellData.dwIATSectionBase), g_stcShellData.dwIATSectionSize,
// 		dwOldProtect, &dwOldProtect);

}


// 函数说明:	修复重定位
void RecReloc()
{
	typedef struct _TYPEOFFSET
	{
		WORD offset : 12;		//偏移值
		WORD Type : 4;			//重定位属性(方式)
	}TYPEOFFSET, *PTYPEOFFSET;

	//1.获取重定位表结构体指针
	PIMAGE_BASE_RELOCATION	pPEReloc=
		(PIMAGE_BASE_RELOCATION)(dwImageBase + g_stcShellData.stcPERelocDir.VirtualAddress);
	
	//2.开始修复重定位
	while (pPEReloc->VirtualAddress)
	{
		//2.1修改内存属性为可写
		DWORD dwOldProtect = 0;
		g_pfnVirtualProtect((PBYTE)dwImageBase + pPEReloc->VirtualAddress,
			0x1000, PAGE_EXECUTE_READWRITE, &dwOldProtect);

		//2.2修复重定位
		PTYPEOFFSET pTypeOffset = (PTYPEOFFSET)(pPEReloc + 1);
		DWORD dwNumber = (pPEReloc->SizeOfBlock - 8) / 2;
		for (DWORD i = 0; i < dwNumber; i++)
		{
			if (*(PWORD)(&pTypeOffset[i]) == NULL)
				break;
			//RVA
			DWORD dwRVA = pTypeOffset[i].offset + pPEReloc->VirtualAddress;
			//FAR地址
			DWORD AddrOfNeedReloc = *(PDWORD)((DWORD)dwImageBase + dwRVA);
			*(PDWORD)((DWORD)dwImageBase + dwRVA) = 
				AddrOfNeedReloc - g_stcShellData.dwPEImageBase + dwImageBase;
		}

		//2.3恢复内存属性
		g_pfnVirtualProtect((PBYTE)dwImageBase + pPEReloc->VirtualAddress,
			0x1000, dwOldProtect, &dwOldProtect);

		//2.4修复下一个区段
		pPEReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pPEReloc + pPEReloc->SizeOfBlock);
	}
}


// 函数说明: 解密异或机器码的情况
void DeXorMachineCode()
{
	PBYTE pCodeBase = (PBYTE)g_stcShellData.dwCodeBase + dwImageBase;
	DWORD dwOldProtect = 0;
	g_pfnVirtualProtect(pCodeBase, g_stcShellData.dwXorSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	//密机器码绑定
	char MachineCode[16] = { 0 };
	__asm
	{
		mov eax, 00h
			xor edx, edx
			cpuid
			mov dword ptr MachineCode[0], edx
			mov dword ptr MachineCode[4], eax
	}
	__asm
	{
		mov eax, 01h
			xor ecx, ecx
			xor edx, edx
			cpuid
			mov dword ptr MachineCode[8], edx
			mov dword ptr MachineCode[12], ecx
	}
	DWORD j = 0;
	for (DWORD i = 0; i < g_stcShellData.dwXorSize; i++)
	{
		pCodeBase[i] ^= MachineCode[j++];
		if (j == 16)
			j = 0;
	}
	g_pfnVirtualProtect(pCodeBase, g_stcShellData.dwXorSize, dwOldProtect, &dwOldProtect);
}


// 函数说明:	解密代码段
void DeXorCode()
{
	PBYTE pCodeBase = (PBYTE)g_stcShellData.dwCodeBase + dwImageBase;
	DWORD dwOldProtect = 0;
	g_pfnVirtualProtect(pCodeBase, g_stcShellData.dwXorSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	for (DWORD i = 0; i < g_stcShellData.dwXorSize; i++)
	{
		pCodeBase[i] ^= i;
	}

	g_pfnVirtualProtect(pCodeBase, g_stcShellData.dwXorSize, dwOldProtect, &dwOldProtect);
}


// 函数说明:	初始化函数指针和变量
void InitFun()
{
	//从Kenel32中获取函数
	HMODULE hKernel32		= GetKernel32Addr();
	g_pfnGetProcAddress		= (fnGetProcAddress)MyGetProcAddress();
	g_pfnLoadLibraryA		= (fnLoadLibraryA)g_pfnGetProcAddress(hKernel32, "LoadLibraryA");
	g_pfnGetModuleHandleA	= (fnGetModuleHandleA)g_pfnGetProcAddress(hKernel32, "GetModuleHandleA");
	g_pfnVirtualProtect		= (fnVirtualProtect)g_pfnGetProcAddress(hKernel32, "VirtualProtect");
	g_pfnExitProcess		= (fnExitProcess)g_pfnGetProcAddress(hKernel32, "ExitProcess");
	g_pfnVirtualAlloc		= (fnVirtualAlloc)g_pfnGetProcAddress(hKernel32, "VirtualAlloc");

	
	//从user32中获取函数
	HMODULE hUser32			= g_pfnLoadLibraryA("user32.dll");
	HMODULE hGdi32			= g_pfnLoadLibraryA("gdi32.dll");

	
	//初始化镜像基址
	dwImageBase =			(DWORD)g_pfnGetModuleHandleA(NULL);

	//
	g_pTRUEIAT = (PDWORD)g_pfnVirtualAlloc(0, sizeof(DWORD)*g_stcShellData.dwNumOfIATFuns,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	dwTemp1 = sizeof(DWORD)+3;
	dwTemp2 = sizeof(DWORD)-1;
	dwTemp3 = sizeof(DWORD)*sizeof(DWORD)-dwTemp2;
}


// 函数说明:	通过 PEB 获取Kernel32加载基址
HMODULE GetKernel32Addr()
{
	HMODULE dwKernel32Addr = 0;
	__asm
	{
		push eax
			mov eax, dword ptr fs : [0x30]   // eax = PEB的地址
			mov eax, [eax + 0x0C]            // eax = 指向PEB_LDR_DATA结构的指针
			mov eax, [eax + 0x1C]            // eax = 模块初始化链表的头指针InInitializationOrderModuleList
			mov eax, [eax]                   // eax = 列表中的第二个条目
			mov eax, [eax]                   // eax = 列表中的第三个条目
			mov eax, [eax + 0x08]            // eax = 获取到的Kernel32.dll基址(Win7下第三个条目是Kernel32.dll)
			mov dwKernel32Addr, eax
			pop eax
	}
	return dwKernel32Addr;
}



// 函数说明:	获取 GetProcAddresss
DWORD MyGetProcAddress()
{
	HMODULE hModule = GetKernel32Addr();

	//1.获取DOS头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(PBYTE)hModule;
	//2.获取NT头
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDosHeader->e_lfanew);
	//3.获取导出表的结构体指针
	PIMAGE_DATA_DIRECTORY pExportDir =
		&(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);

PIMAGE_EXPORT_DIRECTORY pExport =
(PIMAGE_EXPORT_DIRECTORY)((PBYTE)hModule + pExportDir->VirtualAddress);

//EAT
PDWORD pEAT = (PDWORD)((DWORD)hModule + pExport->AddressOfFunctions);
//ENT
PDWORD pENT = (PDWORD)((DWORD)hModule + pExport->AddressOfNames);
//EIT
PWORD pEIT = (PWORD)((DWORD)hModule + pExport->AddressOfNameOrdinals);

//4.遍历导出表，获取GetProcAddress()函数地址
DWORD dwNumofFun = pExport->NumberOfFunctions;
DWORD dwNumofName = pExport->NumberOfNames;
for (DWORD i = 0; i < dwNumofFun; i++)
{
	//如果为无效函数，跳过
	if (pEAT[i] == NULL)
		continue;
	//判断是以函数名导出还是以序号导出
	DWORD j = 0;
	for (; j < dwNumofName; j++)
	{
		if (i == pEIT[j])
		{
			break;
		}
	}
	if (j != dwNumofName)
	{
		//如果是函数名方式导出的
		//函数名
		char* ExpFunName = (CHAR*)((PBYTE)hModule + pENT[j]);
		//进行对比,如果正确返回地址
		if (!strcmp(ExpFunName, "GetProcAddress"))
		{
			return pEAT[i] + pNtHeader->OptionalHeader.ImageBase;
		}
	}
	else
	{
		//序号
	}
}
return 0;
}

// 函数说明: 手动调用被加壳程序的 TLS 回调函数(如果有)
void CallTLS()
{
	IMAGE_DOS_HEADER* lpDosHeader = (IMAGE_DOS_HEADER*)dwImageBase;
	IMAGE_NT_HEADERS* lpNtHeader = (IMAGE_NT_HEADERS*)(lpDosHeader->e_lfanew + dwImageBase);

	// 如果被加壳程序的 TLS 可用,则需要调用其回调函数
	if (g_stcShellData.bIsTLSUseful == TRUE)
	{
		// 将 TLS 回调函数表指针设置回去
		PIMAGE_TLS_DIRECTORY pTLSDir =
			(PIMAGE_TLS_DIRECTORY)(lpNtHeader->OptionalHeader.DataDirectory[9].VirtualAddress + dwImageBase);
		pTLSDir->AddressOfCallBacks = g_stcShellData.TLSCallBackFuncRva;
		
		PIMAGE_TLS_CALLBACK* lpTLSFun =
			(PIMAGE_TLS_CALLBACK*)(g_stcShellData.TLSCallBackFuncRva-lpNtHeader->OptionalHeader.ImageBase + dwImageBase);
		while ((*lpTLSFun) != NULL)
		{
			(*lpTLSFun)((PVOID)dwImageBase, DLL_PROCESS_ATTACH, NULL);
			lpTLSFun++;
		}
	}
}

// 函数说明: 混淆
void _stdcall FusedFunc(DWORD funcAddress)
{
	_asm
	{
		jmp label1
		label2:
		_emit 0xeb;        // 跳到下边的 CALL
		_emit 0x04; 
		CALL DWORD PTR DS : [EAX + EBX * 2 + 0x123402EB];       // 执行 EB 02 也就是跳到下一条指令
		
		_emit 0xE8;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;

						    // 跳到下边的 CALL
		_emit 0xEB;
		_emit 0x0E;

							// 混淆部分
		PUSH  0x0;
		PUSH  0x0;
		MOV   EAX, DWORD PTR FS : [0];
		PUSH  EAX;

		CALL  DWORD PTR DS : [EAX + EBX * 2 + 0x5019c083];
		push  funcAddress;  // 这里如果是参数传入的需要注意上面的 add eax, ?? 的 ??
		retn;


		jmp   label3
							// 混淆部分
			_emit 0xE8;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;

	label1:
		jmp label2;
			label3:
	}
}

// 函数说明: 窗口回调函数
LRESULT CALLBACK PSWWCndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	HWND hButton;
	static HWND hEdit;
	switch (uMsg)
	{
	case WM_CREATE:
	{
		hEdit = CreateWindowExW(0, L"edit", L"请输入密码", WS_CHILD | WS_VISIBLE | WS_BORDER, 50, 50, 130, 20, hWnd, (HMENU)0x1001, NULL, NULL);
		hButton = CreateWindowExW(0, L"Button", L"确定", WS_CHILD | WS_VISIBLE, 185, 50, 40, 20, hWnd, (HMENU)1002, NULL, NULL);
	}
	break;
	case WM_COMMAND:
	{
		if (LOWORD(wParam) == 1002)
		{
			TCHAR Text[10];
			GetWindowText(hEdit, Text, 10);
			if (!wcscmp(Text, L"123"))
			{
				key = false;
				PostQuitMessage(0);
			
			}
			else
			{
				key = false;
				ExitProcess(0);
			}
		}
	}
	break;
	default:
		break;
	}

	return DefWindowProcW(hWnd, uMsg, wParam, lParam);
}


// 函数说明: 密码框
void PswBox()
{
	//设计一个窗口类
	WNDCLASS wce = {};
	wce.lpfnWndProc = PSWWCndProc;
	wce.lpszClassName = L"FKBUG1";
	//注册窗口类
	if (0 == RegisterClassW(&wce))
	{
		MessageBoxW(NULL, L"注册密码窗口类失败", L"FKBUG", MB_OK);
	}

	HFONT hSysFont = (HFONT)::GetStockObject(SYSTEM_FONT);
	// 创建窗口
	HWND hWnd = CreateWindowExW(0, L"FKBUG1", L"FKBUG", WS_OVERLAPPEDWINDOW | CW_USEDEFAULT, 300, 150, 200, 200, NULL, NULL, NULL, NULL);
	SendMessage(hWnd, WM_SETFONT, (WPARAM)hSysFont, TRUE);

	if ( 0 == hWnd)
	{
		MessageBoxW(NULL, L"创建窗口失败", L"FKBUG",  MB_OK);
	}
	ShowWindow(hWnd, SW_SHOW);
	UpdateWindow(hWnd);
	MSG msg = {};
	while (GetMessageW(&msg, nullptr, 0, 0) && key == true)
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return;
}


