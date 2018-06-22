#include "stdafx.h"
#include "Cbp_About.h"

Cbp_About::Cbp_About()
{
}


Cbp_About::~Cbp_About()
{

}


// T 设置单步执行命令    
void Cbp_About::SetBP_TF(HANDLE hTrhead) 
{
	CONTEXT ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(hTrhead, &ct))
	{
		printf("获取线程环境失败\n");
	}
	EFLAGS* pEflag = (EFLAGS*)&ct.EFlags;
	pEflag->TF = 1;
	if (!SetThreadContext(hTrhead, &ct))
	{
		printf("设置线程环境失败\n");
	}
}

void Cbp_About::RemoveBP_TF(HANDLE hThread)
{
	CONTEXT ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(hThread, &ct))
	{
		printf("获取线程环境失败\n");
	}
	EFLAGS* pEflag = (EFLAGS*)&ct.EFlags;
	pEflag->TF = 0;
	if (!SetThreadContext(hThread, &ct))
	{
		printf("设置线程环境失败\n");
	}
}


// 硬件断点处理部分：

// 设置硬件断点命令
BOOL Cbp_About::SetBP_HARD(HANDLE hThread, ULONG_PTR uAddress, DWORD Type, DWORD Len, BOOL delflag)
{
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	if (!GetThreadContext(hThread, &ct))
	{
		printf("获取线程环境失败\n");
	}

	// 根据长度对地址进行对齐处理(向上取整)
	if (Len == 1)    // 长度为 2 时地址需要 2 字节对齐
		uAddress = uAddress - uAddress % 2;
	if (Len == 3)    // 长度为 4 时地址需要 4 字节对齐
		uAddress = uAddress - uAddress % 4;


	// 找坑儿, 哪个坑儿没被占就使哪个
	DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;
	if (pDr7->L0 == 0) {  
		
		// RW 为 0 表示为执行断点
		pDr7->L0 = 1;
		ct.Dr0 = uAddress;
		pDr7->RW0 = Type;
		pDr7->LEN0 = Len;
		
	}
	else if (pDr7->L1 == 0) {
		pDr7->L1 = 1;
		ct.Dr1 = uAddress;
		pDr7->RW1 = Type;
		pDr7->LEN1 = Len;
	}
	else if (pDr7->L2 == 0) {
		pDr7->L2 = 1;
		ct.Dr2 = uAddress;
		pDr7->RW2 = Type;
		pDr7->LEN2 = Len;
	}
	else if (pDr7->L3 == 0) {
		pDr7->L3 = 1;
		ct.Dr3 = uAddress;
		pDr7->RW3 = Type;
		pDr7->LEN3 = Len;
	}
	else
	{
		return FALSE;
	}
	if (!SetThreadContext(hThread, &ct))
	{
		printf("输入不合法或未知错误\n");
	}
	BP_HARD BpHard;
	BpHard.address = uAddress;
	BpHard.delFlag = delflag;
	BpHard.Len = Len;
	BpHard.Type = Type;

	m_Vec_HARD.push_back(BpHard);

	return 0;
}

// 移除硬件断点命令, 最后一个参数表示是触发异常时去掉一次性断点还是用户操作直接移除断点
void Cbp_About::RemoveBP_HARD(HANDLE hThread, SIZE_T Address, bool bc)
{
	//需要用到DR6 DR7 寄存器,还有Dr0
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_ALL;

	if (!GetThreadContext(hThread, &ct))
	{
		printf("获取线程环境失败\n");
	}
	DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;


	std::vector<Cbp_About::BP_HARD>::iterator iterHard;
	for (iterHard = m_Vec_HARD.begin(); iterHard != m_Vec_HARD.end(); )
	{
		// 是用户输入要删除的断点，找对了就直接删了
		if (bc)
		{
			if (Address == iterHard->address)
			{
				iterHard = m_Vec_HARD.erase(iterHard);
				printf("硬件断点 %x   已删除\n", iterHard->address);
				if (ct.Dr0 == Address)
				{
					pDr7->L0 = 0;
				}
				else if (ct.Dr1 == Address)
				{
					pDr7->L1 = 0;
				}
				else if (ct.Dr2 == Address)
				{
					pDr7->L2 = 0;
				}
				else if (ct.Dr3 == Address)
				{
					pDr7->L3 = 0;
				}
			}
			else
			{
				iterHard++;
			}
		}
		// 是异常触发得断点，为一次性断点才移除
		else
		{
			// 找到触发异常的断点
			if (Address == iterHard->address )
			{
				// 如果是硬件数据访问断点，触发时已经执行了这条指令了，而且因为没办法计算这条指令的长度，所以很难通过直接操作eip的方式回退回去
				// 所以只能直接设一个单步
  				if (iterHard->Type == BP_HARD_RWDATA)
  				{
 						
 					}
				// 一次性断点就删除并将清理中断寄存器
				if (iterHard->delFlag)
				{
					printf("硬件断点 %x   已删除\n", iterHard->address);
					iterHard = m_Vec_HARD.erase(iterHard);
					if (ct.Dr0 == Address)
					{
						pDr7->L0 = 0;
					}
					else if (ct.Dr1 == Address)
					{
						pDr7->L1 = 0;
					}
					else if (ct.Dr2 == Address)
					{
						pDr7->L2 = 0;
					}
					else if (ct.Dr3 == Address)
					{
						pDr7->L3 = 0;
					}
				}	
				else
				{
					iterHard++;
				}
			}
			else
			{
				iterHard++;
			}
		}
		
	}

	if (!SetThreadContext(hThread, &ct))
	{
		printf("输入不合法或未知错误\n");
	}

	return;
}

void Cbp_About::SetBP_MEM(HANDLE hProcess, SIZE_T Address, BOOL delflag)
{
	// 存储原来的页面属性
	DWORD dwOldProtect = 0;

	// 修改下断地址所在页属性
	VirtualProtectEx(hProcess, (LPVOID)Address, 1, PAGE_NOACCESS, &dwOldProtect);

	// 将内存访问断点存到内存断点数组中
	BP_MEM bpMem = { 0 };
	bpMem.address = Address;
	bpMem.dwOldAttri = dwOldProtect;
	bpMem.delFlag = delflag;
	
	m_Vec_Mem.push_back(bpMem);
}

BOOL Cbp_About::SetBP_Condition(HANDLE hProcess, SIZE_T Address, BOOL ConditionWay, DWORD EndTimes, DWORD EndVaule, Eregister Reg)
{
	// 1. 读取断点所在的内存的1字节的内容保存
	BP_CONDITION bp_Condition = { 0 };
	DWORD dwRead = 0;
	if (!ReadProcessMemory(hProcess, (LPVOID)Address, &bp_Condition.oldbyte, 1, &dwRead)) {
		LOG("读取内存失败");
		return false;
	}
	// 2. 将int 3指令(0xcc)写入到断点的地址上
	if (!WriteProcessMemory(hProcess, (LPVOID)Address, "\xcc", 1, &dwRead)) {
		LOG("写入内存失败");
		return false;
	}
	bp_Condition.address = Address;
	bp_Condition.ConditionWay = ConditionWay;
	bp_Condition.Times = 0;
	bp_Condition.EndTimes = EndTimes;
	bp_Condition.Reg = Reg;
	bp_Condition.EndValue = EndVaule;

	// 3. 保存断点信息
	m_Vec_Condition.push_back(bp_Condition);
	return 0;
}





// 软件断点处理部分：


// 设置软件断点
BOOL Cbp_About::SetBP_INT3(HANDLE hProc, SIZE_T address, bool delflag)
{
	// 1. 读取断点所在的内存的1字节的内容保存
	BP_INT3 bp = { 0 };
	DWORD dwRead = 0;
	if (!ReadProcessMemory(hProc, (LPVOID)address, &bp.oldbyte, 1, &dwRead)) {
		LOG("读取内存失败");
		return false;
	}
	// 2. 将int 3指令(0xcc)写入到断点的地址上
	if (!WriteProcessMemory(hProc, (LPVOID)address, "\xcc", 1, &dwRead)) {
		LOG("写入内存失败");
		return false;
	}
	bp.address = address;
	bp.delFlag = delflag;
	// 3. 保存断点信息
	m_Vec_INT3.push_back(bp);
	
	return true;
}


