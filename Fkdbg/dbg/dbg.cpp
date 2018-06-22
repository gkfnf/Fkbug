// dbg.cpp : 定义控制台应用程序的入口点。
//
#pragma once
#include "stdafx.h"
#include "CmyDebug.h"



BOOL hookIAT(const char * pszDllName, const char * pszFunc, LPVOID pNewFunc)
{
	HANDLE hProc = GetCurrentProcess();

	PIMAGE_DOS_HEADER			pDosHeader;			// Dos头
	PIMAGE_NT_HEADERS			pNtHeader;			// Nt头
	PIMAGE_IMPORT_DESCRIPTOR	pImpTable;	// 导入表
	PIMAGE_THUNK_DATA			pInt;					  // 导入表中的导入名称表
	PIMAGE_THUNK_DATA			pIat;		        // 导入表中的导入地址表
	DWORD						dwSize;
	DWORD						hModule;
	char*						pFunctionName;
	DWORD						dwOldProtect;

	hModule = (DWORD)GetModuleHandle(NULL);

	// 读取dos头
	pDosHeader = (PIMAGE_DOS_HEADER)hModule;

	// 读取Nt头
	pNtHeader = (PIMAGE_NT_HEADERS)(hModule + pDosHeader->e_lfanew);


	// 获取导入表
	pImpTable = (PIMAGE_IMPORT_DESCRIPTOR)
		(hModule + pNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress);

	// 遍历导入表
	while (pImpTable->FirstThunk != 0 && pImpTable->OriginalFirstThunk != 0) {


		// 判断是否找到了对应的模块名
		if (_stricmp((char*)(pImpTable->Name + hModule), pszDllName) != 0) {
			++pImpTable;
			continue;
		}

		// 遍历名称表,找到函数名
		pInt = (PIMAGE_THUNK_DATA)(pImpTable->OriginalFirstThunk + hModule);
		pIat = (PIMAGE_THUNK_DATA)(pImpTable->FirstThunk + hModule);

		while (pInt->u1.AddressOfData != 0) {

			// 判断是以名称导入还是以需要导入
			if (pInt->u1.Ordinal & 0x80000000 == 1) {
				// 以序号导入

				// 判断是否找到了对应的函数序号
				if (pInt->u1.Ordinal == ((DWORD)pszFunc) & 0xFFFF) {
					// 找到之后,将钩子函数的地址写入到iat
					VirtualProtect(&pIat->u1.Function,
						4,
						PAGE_READWRITE,
						&dwOldProtect
					);

					pIat->u1.Function = (DWORD)pNewFunc;

					VirtualProtect(&pIat->u1.Function,
						4,
						dwOldProtect,
						&dwOldProtect
					);
					return true;
				}
			}
			else {
				// 以名称导入
				pFunctionName = (char*)(pInt->u1.Function + hModule + 2);

				// 判断是否找到了对应的函数名
				if (strcmp(pszFunc, pFunctionName) == 0) {

					VirtualProtect(&pIat->u1.Function,
						4,
						PAGE_READWRITE,
						&dwOldProtect
					);

					// 找到之后,将钩子函数的地址写入到iat
					pIat->u1.Function = (DWORD)pNewFunc;

					VirtualProtect(&pIat->u1.Function,
						4,
						dwOldProtect,
						&dwOldProtect
					);

					return true;
				}
			}

			++pIat;
			++pInt;
		}


		++pImpTable;
	}

	return false;

}


int main()
{
	CmyDebug debuger;
	debuger.EnterDebugLoop();
}


