#include "stdafx.h"
#include "Cdbg_Info.h"


Cdbg_Info::Cdbg_Info()
{
}


Cdbg_Info::~Cdbg_Info()
{
}




void Cdbg_Info::showDebugInfor(HANDLE hProc, HANDLE hThread, LPVOID address)
{

	CONTEXT ct = { CONTEXT_ALL };
	GetThreadContext(hThread, &ct);

	// 获取寄存器信息
	printf("EIP:%08X EAX:%X ECX:%X EDX:%X\n",
		ct.Eip,
		ct.Eax,
		ct.Ecx,
		ct.Edx);


	char opcode[200];
	DWORD dwWrite = 0;
	ReadProcessMemory(hProc, address, opcode, 200, &dwWrite);

 
  // 获取反汇编信息
	DISASM da = { 0 };
	da.Archi = 0;// 32位汇编
	da.EIP = (UIntPtr)opcode; // 保存opcode的缓冲区地址
	da.VirtualAddr = (UInt64)address;// opcode原先所在的地址

	int nLen = 0;

	int nCount = 20;
	while (nCount-- && -1 != (nLen = Disasm(&da))) {
		printf("%llx | %s\n", da.VirtualAddr, da.CompleteInstr);
		da.VirtualAddr += nLen;
		da.EIP += nLen;
	}
}
