#include "stdafx.h"
#include "CmyDebug.h"
#include "Cdbg_Info.h"


CmyDebug::CmyDebug()
{
	//m_context.ContextFlags = CONTEXT_ALL;    // 设置线程上下文访问权限
	m_MemStep = false;
	m_ConditionStep = false;
	m_Oep = false;
}


CmyDebug::~CmyDebug()
{
}

//  创建调试会话
void CmyDebug::CreateDebug()
{
	printf("exe:");
	// 取文件路径来创建调试会话

	gets_s(m_path, MAX_PATH);

	//先保存缓冲区
	TCHAR Tea[MAX_PATH] = {};
	MultiByteToWideChar(CP_ACP, NULL, m_path, -1, Tea, MAX_PATH);

	DWORD dwHeight = 0;
	DWORD dwFileSize = 0;

	m_Size = GetFileSize(m_hfile, &dwHeight);
	m_pBuff = new BYTE[dwFileSize]{};

	DWORD rea = 0;

	ReadFile(m_hfile, m_pBuff, dwFileSize, &rea, NULL);
	
	//CloseHandle(m_hfile);

	STARTUPINFOA si = { sizeof(STARTUPINFOA) };
	PROCESS_INFORMATION pi = { 0 };
	BOOL ret = 0;
	ret = CreateProcessA(m_path,
		NULL,
		NULL,
		NULL,
		FALSE,
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&si,
		&pi);

	assert(ret);
	return;
}

// 微软的调试器框架
void CmyDebug::EnterDebugLoop()
{
	CreateDebug();

	DWORD dwContinueStatus = DBG_CONTINUE;     // exception continuation 
	DEBUG_EVENT dbgEvent = { 0 };
	HANDLE hProcess = { 0 };
	HANDLE hThread = { 0 };

	for (;;)
	{
		WaitForDebugEvent(&dbgEvent, INFINITE);

		m_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dbgEvent.dwProcessId);
		m_Thread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
  
		switch (dbgEvent.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:	
			dwContinueStatus = OnExceptionDebugEvent(dbgEvent);
			break;
		case CREATE_THREAD_DEBUG_EVENT:printf(" 线程创建事件\n");  break;
		case CREATE_PROCESS_DEBUG_EVENT:
			printf(" 进程创建事件\n"); 
			m_bpAbout.SetBP_INT3(m_process, (SIZE_T)dbgEvent.u.CreateProcessInfo.lpStartAddress, true);
			printf("设置 OEP 断点\n");
			m_Oep = true;

			m_processID = dbgEvent.dwProcessId;
			break;
		case EXIT_THREAD_DEBUG_EVENT:   printf(" 退出线程事件\n"); break;
		case EXIT_PROCESS_DEBUG_EVENT:  printf(" 退出进程事件\n"); break;
		case LOAD_DLL_DEBUG_EVENT:      printf(" 映射DLL事件\n"); break;
		case UNLOAD_DLL_DEBUG_EVENT:    printf(" 卸载DLL事件\n"); break;
		case OUTPUT_DEBUG_STRING_EVENT: printf(" 调试字符串输出事件\n"); break;
		case RIP_EVENT:                 printf(" RIP事件(内部错误)\n"); break;
		}

		// Resume executing the thread that reported the debugging event. 

		// 被调试进程结束时释放资源
		CloseHandle(hThread);         
		CloseHandle(hProcess);

		ContinueDebugEvent(dbgEvent.dwProcessId,dbgEvent.dwThreadId,dwContinueStatus);
	}


}

void CmyDebug::showDisasm(HANDLE hProc, LPVOID address, int nLen)
{
	// system("cls");

	// 1. 将进程的内存读取过来
	// 2. 使用反汇编引擎扫描内存,获取反汇编
	// 3. 输出反汇编

	BYTE  OPcode[512];
	DWORD dwRead = 0;
	DWORD dwOldProtect = 0;        // 存储原来的页面属性
	
	// 修改页面属性
	VirtualProtectEx(m_process, (LPVOID)address, 512, PAGE_READWRITE, &dwOldProtect);
	ReadProcessMemory(m_process, (LPVOID)address, OPcode, 512, &dwRead);
	VirtualProtectEx(m_process, (LPVOID)address, 512, dwOldProtect, &dwOldProtect);
	if (dwRead != 512)
	{
		printf("读取内存失败\n");
		return;
	}


// 	char* pBuff = new char[nLen * 16];
// 	DWORD dwRead = 0;
// 	if (!ReadProcessMemory(hProc, address, pBuff, nLen * 16, &dwRead))
// 		return;

	
	DISASM d = { 0 };
	CString funName = {};              // 符号信息
	d.EIP = (UIntPtr)OPcode;
	d.VirtualAddr = (UInt64)address;
	int OPcodeSubscript = 0;          // 记录 OPCODE 位置   
	

	while (nLen > 0) {
		int len = Disasm(&d);
		if (len == -1) {
			printf("反汇编出错\n");
			return;
		}
		printf("%08X |", (DWORD)d.VirtualAddr);
		// 一个字节一个字节的打印本条指令长度的 OPCODE
		for (int i = 0; i < len; i++)
		{
			printf("%02X", OPcode[i+OPcodeSubscript]);
		}
		// 7字节差不多 是最长的指令的 OPCODE 长度了
		if (len < 7)
		{
			for (int i = 2*(7 - len); i > 0; i--)
			{
				printf(" ");
			}
		}
		printf(" |");
		printf("%-35s", d.CompleteInstr);
		printf(" |");

		// 如果是个 CALL 或 JMP 就尝试获取符号信息并打印
		if (d.Instruction.Opcode == 0xE8 || d.Instruction.Opcode == 0xEB)
		{
			GetSymFuncName(d.Instruction.AddrValue, funName);
			wprintf(L"%s", funName);
		}
		printf("\n");

		d.EIP += len;
		OPcodeSubscript += len;
		d.VirtualAddr += len;
		--nLen;
	}

	ShowRegister();
	ShowStack();
}

// 接收用户输入进行相应操作
void CmyDebug::userInput(EXCEPTION_RECORD& record)
{
	char cmdLine[512];
	while (true) {
		printf(">");
		scanf_s("%s", cmdLine, 512);

		// 单步命令
		if (_stricmp(cmdLine, "t") == 0) {

			m_bpAbout.SetBP_TF(m_Thread);
			return;   // 退出接收输入
		}

		// 运行命令
		else if (_stricmp(cmdLine, "g") == 0) {
			return;
		}

		// 反汇编命令
		else if (_stricmp(cmdLine, "u") == 0) {
			printf("反汇编长度:");
			int a = 0;
			scanf_s("%d", &a);
			showDisasm(m_process, record.ExceptionAddress, a);
		}
		
		// 查看模块命令
		else if (_stricmp(cmdLine, "module") == 0) {
			TraverseModule(m_processID);
		}

		// dump 转储命令
		else if (_stricmp(cmdLine, "dump") == 0) {
			Dump("转储备份.exe", m_path);
		}
		// 导出表
		else if (_stricmp(cmdLine, "export") == 0) {
			TraverseModule(m_processID);
			printf("要解析的模块:");
			TCHAR mod[512];
			wscanf_s(L"%s", mod, 512);
			PaserExportTable(ModuleToAddr(mod, m_processID));
		}
		else if (_stricmp(cmdLine, "import") == 0) {
			TraverseModule(m_processID);
			printf("要解析的模块:");
			TCHAR mod[512];
			wscanf_s(L"%s", mod, 512);
			PaserImportTable(ModuleToAddr(mod, m_processID));
		}
		// 设置软件断点命令
		else if (_stricmp(cmdLine, "bp") == 0) {
			// 设置软件断点地址  
			printf("输入断点地址(Hex):");
			SIZE_T  address = 0;
			scanf_s("%X", &address);
			// 设置是否为永久性软件断点
			char    forever[10];
			bool    delflag = true;
			printf("是否永久性断点(y/n)：");
			scanf_s("%s", &forever, 10);
			if (_stricmp(forever, "y") == 0)
			{
				delflag = false;
			}
			m_bpAbout.SetBP_INT3(m_process, address, delflag);
		}

		// 设置硬件执行断点命令
		else if (_stricmp(cmdLine, "bae") == 0)
		{
			printf("输入断点地址(Hex):");
			SIZE_T  address = 0;
			scanf_s("%X", &address);
			char    forever[10];
			bool    delflag = true;
			printf("是否永久性断点(y/n)：");
			scanf_s("%s", &forever, 10);
			if (_stricmp(forever, "y") == 0)
			{
				delflag = false;
			}
			m_bpAbout.SetBP_HARD(m_Thread, address, BP_HARD_EXEC, K1_BYTE, delflag);
		}

		// 设置硬件读/写数据断点
		else if (_stricmp(cmdLine, "bar") == 0)
		{
			printf("输入硬件数据访问断点地址(Hex):");
			SIZE_T  address = 0;
			scanf_s("%X", &address);
			char    forever[10];
			bool    delflag = true;
			int     nLen = 0;
			printf("是否永久性断点(y/n)：");
			scanf_s("%s", &forever, 10);
			if (_stricmp(forever, "y") == 0)
			{
				delflag = false;
			}
			printf("数据读写断点长度(1/2/4):");
			scanf_s("%d", &nLen);
			if (nLen >= 1)
			{
				if (nLen % 4 == 0)
				{
					m_bpAbout.SetBP_HARD(m_Thread, address, BP_HARD_RWDATA, K4_BYTE, delflag);
				}
				else if (nLen % 2 == 0)
				{
					m_bpAbout.SetBP_HARD(m_Thread, address, BP_HARD_RWDATA, K2_BYTE, delflag);
				}
				else
				{
					m_bpAbout.SetBP_HARD(m_Thread, address, BP_HARD_RWDATA, K1_BYTE, delflag);
				}
			}
	  }
		
		// 设置硬件写入断点
		else if (_stricmp(cmdLine, "baw") == 0)
		{
			printf("输入写入断点地址(Hex):");
			SIZE_T  address = 0;
			scanf_s("%X", &address);
			char    forever[10];
			bool    delflag = true;
			int     nLen = 0;
			printf("是否永久性断点(y/n)：");
			scanf_s("%s", &forever, 10);
			if (_stricmp(forever, "y") == 0)
			{
				delflag = false;
			}
			printf("硬件写入断点长度(1/2/4):");
			scanf_s("%d", &nLen);
			if (nLen >= 1)
			{
				if (nLen % 4 == 0)
				{
					m_bpAbout.SetBP_HARD(m_Thread, address, BP_HARD_WR, K4_BYTE, delflag);
				}
				else if (nLen % 2 == 0)
				{
					m_bpAbout.SetBP_HARD(m_Thread, address, BP_HARD_WR, K2_BYTE, delflag);
				}
				else
				{
					m_bpAbout.SetBP_HARD(m_Thread, address, BP_HARD_WR, K1_BYTE, delflag);
				}
			}
		}

		// 设置条件断点命令
		else if (_stricmp(cmdLine, "bpif") == 0) {
			printf("输入条件断点地址(HEX): ");
			SIZE_T  address = 0;
			char    ByTimes[10];
			scanf_s("%X", &address);
			bool    conditionway = false;
			printf("输入条件断点方式(y按命中次数/n按寄存器值): ");
			scanf_s("%s", ByTimes, 10);
			if (_stricmp(ByTimes, "y") == 0)
			{
				conditionway = true;
				printf("输入命中次数: ");
				DWORD EndTimes;
				scanf_s("%d", &EndTimes);
				m_bpAbout.SetBP_Condition(m_process, address, conditionway, EndTimes, 0, Cbp_About::e_eax);
			}
			else
			{
				conditionway = false;
				Cbp_About::Eregister reg = Cbp_About::e_eax;
				DWORD EndValue = 0;
				char Reg[10];
				printf("要判断的寄存器(eax/ebx/ecx/edx/esp/ebp/esi/edi/cs/ss/ds/es/fs): ");
				scanf_s("%s", &Reg, 10);
				if (_stricmp(Reg, "eax") == 0)
				{
					reg = Cbp_About::e_eax;
				}
				else if (_stricmp(Reg, "ebx") == 0)
				{
					reg = Cbp_About::e_ebx;
				}
				else if (_stricmp(Reg, "ecx") == 0)
				{
					reg = Cbp_About::e_ecx;
				}
				else if (_stricmp(Reg, "edx") == 0)
				{
					reg = Cbp_About::e_edx;
				}
				else if (_stricmp(Reg, "ebx") == 0)
				{
					reg = Cbp_About::e_ebx;
				}
				else if (_stricmp(Reg, "esp") == 0)
				{
					reg = Cbp_About::e_esp;
				}
				else if (_stricmp(Reg, "ebp") == 0)
				{
					reg = Cbp_About::e_ebp;
				}
				else if (_stricmp(Reg, "esi") == 0)
				{
					reg = Cbp_About::e_esi;
				}
				else if (_stricmp(Reg, "edi") == 0)
				{
					reg = Cbp_About::e_edi;
				}
				else if (_stricmp(Reg, "cs") == 0)
				{
					reg = Cbp_About::e_ecs;
				}
				else if (_stricmp(Reg, "ds") == 0)
				{
					reg = Cbp_About::e_eds;
				}
				else if (_stricmp(Reg, "ss") == 0)
				{
					reg = Cbp_About::e_ess;
				}
				else if (_stricmp(Reg, "es") == 0)
				{
					reg = Cbp_About::e_ees;
				}
				else if (_stricmp(Reg, "fs") == 0)
				{
					reg = Cbp_About::e_efs;
				}
				else if (_stricmp(Reg, "gs") == 0)
				{
					reg = Cbp_About::e_egs;
				}
				printf("寄存器满足条件的值(HEX):");
				scanf_s("%x", &EndValue);
				m_bpAbout.SetBP_Condition(m_process, address, conditionway, 0, EndValue, reg);
			}
		}

		// 列举断点命令
		else if (_stricmp(cmdLine, "bl") == 0){	
			printf("软件断点:\n");
			for (auto& i : m_bpAbout.m_Vec_INT3)
			{
				printf("         地址: %4x     永久性:%d\n", i.address, !i.delFlag);
			}
			
			printf("硬件断点:\n");
			for (auto& h : m_bpAbout.m_Vec_HARD)
			{
				printf("         地址: %4x     永久性:%d", h.address, !h.delFlag);
				switch (h.Type)
				{
				case BP_HARD_EXEC:
					printf("    硬断类型:  执行断点\n");
					break;
				case BP_HARD_WR:
					printf("    硬断类型:  写入断点\n");
					break;
				case BP_HARD_RWDATA:
					printf("    硬断类型:  数据读写断点\n");
					break;
				default:
					break;
				}				
			}
			
			printf("内存断点:\n");
			for (auto& i : m_bpAbout.m_Vec_Mem)
			{
				printf("         地址: %4x     永久性:%d\n", i.address, !i.delFlag);
// 				switch (i.dwOldAttri)
// 				{
// 
// 				}
			}
		}

		// 设置内存断点命令
		else if (_stricmp(cmdLine, "bm") == 0) {

			// 设置软件断点地址  
			printf("输入断点地址(Hex):");
			SIZE_T  address = 0;
			scanf_s("%X", &address);
			// 设置是否为永久性软件断点
			char    forever[10];
			bool    delflag = true;
			printf("是否永久性断点(y/n)：");
			scanf_s("%s", &forever, 10);
			if (_stricmp(forever, "y") == 0)
			{
				delflag = false;
			}
			m_bpAbout.SetBP_MEM(m_process, address, delflag);
		}

		// 删除对应断点命令
		else if (_stricmp(cmdLine, "bc") == 0)
		{
			printf("要删除的断点地址:");
			SIZE_T deladdr = 0;
			scanf_s("%x", &deladdr, sizeof(SIZE_T));
			std::vector<Cbp_About::BP_INT3>::iterator iter;
			for ( iter = m_bpAbout.m_Vec_INT3.begin(); iter != m_bpAbout.m_Vec_INT3.end(); )
			{
				if (iter->address == deladdr)
				{
					DWORD dwWrite;
					if (!WriteProcessMemory(m_process, (LPVOID)iter->address, &iter->oldbyte, 1, &dwWrite)) 
					{
						LOG("读取进程内存失败");
					}
					printf("软件断点 %x   已删除\n", iter->address);
					iter = m_bpAbout.m_Vec_INT3.erase(iter);			
				}
				else
				{
						iter++;
				}
			}		

			m_bpAbout.RemoveBP_HARD(m_Thread, deladdr, true);
			

		}

		// 清除所有断点命令
		else if (_stricmp(cmdLine, "bc*") == 0) {
			std::vector<Cbp_About::BP_INT3>::iterator iter;
			for (iter = m_bpAbout.m_Vec_INT3.begin(); iter != m_bpAbout.m_Vec_INT3.end(); )
			{
				DWORD dwWrite;
				if (!WriteProcessMemory(m_process, (LPVOID)iter->address, &iter->oldbyte, 1, &dwWrite))
				{
					LOG("读取进程内存失败");
				}
				iter = m_bpAbout.m_Vec_INT3.erase(iter);
			}
			// 清除所有硬件断点
			CONTEXT ct = { 0 };
			ct.ContextFlags = CONTEXT_DEBUG_REGISTERS;

			if (!GetThreadContext(m_Thread, &ct))
			{
				printf("获取线程环境失败\n");
			}
			DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;
			pDr7->L0 = 0;
			pDr7->L1 = 0;
			pDr7->L2 = 0;
			pDr7->L3 = 0;
			if (!SetThreadContext(m_Thread, &ct))
			{
				printf("输入不合法或未知错误\n");
			}

			m_bpAbout.m_Vec_HARD.clear();

			// 清除所有内存访问断点
		}

		else
		{
			printf("输入错误\n");
		}

	}
}

// 调试异常事件时输出反汇编代码并接收用户的输入并根据用户输入对命令进行对应处理
DWORD CmyDebug::OnExceptionDebugEvent(DEBUG_EVENT dbgEv)
{
	// 把所有的断点重新下一遍.
	DWORD dwCode = DBG_CONTINUE;

	switch (dbgEv.u.Exception.ExceptionRecord.ExceptionCode) {
	case EXCEPTION_BREAKPOINT:                // 软件异常
	{
		dwCode = OnExceptionINT3(dbgEv.u.Exception.ExceptionRecord);
	}
	break;
	case EXCEPTION_SINGLE_STEP:               // 单步异常和硬件断点异常
	{
		// tf断点每次中断之后都会被自动置零.
		dwCode = OnExceptionSingleStep(dbgEv.u.Exception.ExceptionRecord);
	}
	break;
	case EXCEPTION_ACCESS_VIOLATION:          // 内存访问异常
	{
		dwCode = OnExceptionMem(dbgEv);
	}
	break;
	default:
	{
		dwCode = DBG_EXCEPTION_NOT_HANDLED;
		break;
	}
		
	}

	return dwCode;
}

DWORD CmyDebug::OnExceptionINT3(EXCEPTION_RECORD & record)
{
	static BOOL isSystemBreakpoint = TRUE;
	DWORD dwCode = DBG_CONTINUE;

	// 系统断点的特征:
	// 第一个异常事件.而且, 异常代码是BREAKPOINT
	// 是否是系统断点
	if (isSystemBreakpoint) {
		if (record.ExceptionCode == EXCEPTION_BREAKPOINT) {
			// 系统断点
			dwCode = DBG_CONTINUE;
			printf("到达系统断点:%08X\n", record.ExceptionAddress);
		}
		CONTEXT ct = { CONTEXT_CONTROL };
		if (!GetThreadContext(m_Thread, &ct))
		{
			printf("获取线程环境失败\n");
		}
		isSystemBreakpoint = FALSE;
		showDisasm(m_process, (LPVOID)ct.Eip, 20);
		//showDisasm(m_process, record.ExceptionAddress, 20);
		// 接收用户输入
		userInput(record);
		return dwCode;
	}

	// 去除软件断点引起的软件断点异常
	std::vector<Cbp_About::BP_INT3>::iterator iter;
	for (iter = m_bpAbout.m_Vec_INT3.begin(); iter != m_bpAbout.m_Vec_INT3.end(); )
	{
		if (iter->address == (SIZE_T)record.ExceptionAddress)
		{
			if (m_Oep)
			{
				printf("到达 OEP\n");
				m_Oep = false;
			}

			DWORD dwWrite = 0;
			if (!WriteProcessMemory(m_process, (LPVOID)iter->address, &iter->oldbyte, 1, &dwWrite)) {
				LOG("读取进程内存失败");
				dwCode = DBG_EXCEPTION_NOT_HANDLED;

				return dwCode;
			}
			// 将eip减1
			CONTEXT ct = { CONTEXT_CONTROL };
			if (!GetThreadContext(m_Thread, &ct)) {
				LOG("获取线程环境失败");
				dwCode = DBG_EXCEPTION_NOT_HANDLED;
				return dwCode;
			}
			ct.Eip--;

			if (!SetThreadContext(m_Thread, &ct)) {
				LOG("获取线程环境失败");
				dwCode = DBG_EXCEPTION_NOT_HANDLED;
				return dwCode;
			}
			// 如果是永久性断点，在显示完反汇编后再把 INT3 写回去
			if (iter->delFlag == FALSE)
			{
				SIZE_T dwRead;
				showDisasm(m_process, record.ExceptionAddress, 10);

				WriteProcessMemory(m_process, (LPVOID)iter->address, "\xcc", 1, &dwRead);
				// 接收用户输入
				userInput(record);
				return dwCode;
			}
			// 如果是一次性断点，就需要从软件断点列表中移除
			else
			{
				printf("软件断点  %x   已删除\n", iter->address);
				iter = m_bpAbout.m_Vec_INT3.erase(iter);	
				showDisasm(m_process, record.ExceptionAddress, 20);
				// 接收用户输入
				userInput(record);

				return dwCode;
			}
		}
		else
		{
			iter++;
		}
	}
	
	// 去除条件断点引起的软件断点异常
	std::vector<Cbp_About::BP_CONDITION>::iterator iterCondition;
	for (iterCondition = m_bpAbout.m_Vec_Condition.begin(); iterCondition != m_bpAbout.m_Vec_Condition.end(); )
	{
		if (iterCondition->address == (SIZE_T)record.ExceptionAddress)
		{
			DWORD dwWrite = 0;
			if (!WriteProcessMemory(m_process, (LPVOID)iterCondition->address, &iterCondition->oldbyte, 1, &dwWrite)) {
				LOG("读取进程内存失败");
				dwCode = DBG_EXCEPTION_NOT_HANDLED;
				return dwCode;
			}
			// 将eip减1
			CONTEXT ct = { CONTEXT_CONTROL };
			if (!GetThreadContext(m_Thread, &ct)) {
				LOG("获取线程环境失败");
				dwCode = DBG_EXCEPTION_NOT_HANDLED;
				return dwCode;
			}
			ct.Eip--;

			if (!SetThreadContext(m_Thread, &ct)) {
				LOG("获取线程环境失败");
				dwCode = DBG_EXCEPTION_NOT_HANDLED;
				return dwCode;
			}
			// 如果是按命中次数触发的断点
			if (iterCondition->ConditionWay == TRUE)
			{
				// 每触发一次就加一次次数
				iterCondition->Times++;
				
				// 达到条件次数就删除该断点然后显示反汇编并接管到用户输入
				if (iterCondition->Times == iterCondition->EndTimes)
				{
					printf("条件断点  %x   触发后删除\n", iterCondition->address);
					iterCondition = m_bpAbout.m_Vec_Condition.erase(iterCondition);				
					
					showDisasm(m_process, record.ExceptionAddress, 10);
					
					// 接收用户输入
					userInput(record);
					return dwCode;
				}
				// 没有达到条件次数就设一个单步，然后在单步异常里边将这个条件断点恢复
				else
				{
					m_ConditionStep = true;
					m_bpAbout.SetBP_TF(m_Thread);
					iterCondition++;
					return dwCode;
				}
			}
			// 如果是按寄存器的值触发的
			else
			{
				CONTEXT ct = { CONTEXT_CONTROL };
				if (!GetThreadContext(m_Thread, &ct)) {
					LOG("获取线程环境失败");
					dwCode = DBG_EXCEPTION_NOT_HANDLED;
					return dwCode;
				}

				DWORD TempRegValue = 0;
				switch (iterCondition->Reg)
				{
					case Cbp_About::e_eax:
						TempRegValue = ct.Eax; break;
					case Cbp_About::e_ebx:
						TempRegValue = ct.Ebx; break;
					case Cbp_About::e_ecx:
						TempRegValue = ct.Ecx; break;
					case Cbp_About::e_edx:
						TempRegValue = ct.Edx; break;
					case Cbp_About::e_ebp:
						TempRegValue = ct.Ebp; break;
					case Cbp_About::e_esp:
						TempRegValue = ct.Esp; break;
					case Cbp_About::e_esi:
						TempRegValue = ct.Esi; break;
					case Cbp_About::e_edi:
						TempRegValue = ct.Edi; break;
					case Cbp_About::e_ecs:
						TempRegValue = ct.SegCs; break;
					case Cbp_About::e_ess:
						TempRegValue = ct.SegSs; break;
					case Cbp_About::e_eds:
						TempRegValue = ct.SegDs; break;
					case Cbp_About::e_ees:
						TempRegValue = ct.SegEs; break;
					case Cbp_About::e_efs:
						TempRegValue = ct.SegFs; break;
					case Cbp_About::e_egs:
						TempRegValue = ct.SegGs; break;				
				}

				if (TempRegValue == iterCondition->EndValue)
				{
					printf("条件断点  %x   触发后删除\n", iterCondition->address);
					iterCondition = m_bpAbout.m_Vec_Condition.erase(iterCondition);

					showDisasm(m_process, record.ExceptionAddress, 10);

					// 接收用户输入
					userInput(record);
					return dwCode;
				}
				else
				{
					m_ConditionStep = true;
					m_bpAbout.SetBP_TF(m_Thread);
					iterCondition++;
					return dwCode;
				}		
			}
		}
		else
		{
			iter++;
		}
	}


	showDisasm(m_process,record.ExceptionAddress,20);
	// 接收用户输入
	userInput(record);

	return dwCode;
}

DWORD CmyDebug::OnExceptionSingleStep(EXCEPTION_RECORD & record)
{
	printf("单步异常事件\n");
	DWORD dwCode = DBG_CONTINUE;
	SIZE_T addrStart = (SIZE_T)record.ExceptionAddress - ((SIZE_T)record.ExceptionAddress % 0x1000);
	// 下断地址所在页的页末地址 = 页起始地址 + 页大小
	SIZE_T addrEnd = addrStart + 0xFFF;

	// 如果是内存断点设的单步导致触发的单步异常,则需要恢复内存断点并将 m_MemStep 置为 false
	if (m_MemStep)
	{
		for (auto i : m_bpAbout.m_Vec_Mem)
		{
			// 找到设置单步异常的这个内存断点并重设这个内存断点
			if (addrStart <= i.address && i.address <= addrEnd)
			{
				m_bpAbout.SetBP_MEM(m_process, i.address, i.delFlag);
				m_MemStep = false;
				
				return dwCode;
			}	
		}
		
	} 

	// 如果是条件断点设的单步导致触发的单步异常,则需要恢复条件断点并将 m_MemStep 置为 false
	if (m_ConditionStep)
	{
		for (auto i : m_bpAbout.m_Vec_Condition)
		{
				DWORD dwRead = 0;

				// 将int 3指令(0xcc)写入到断点的地址上
				if (!WriteProcessMemory(m_process, (LPVOID)i.address, "\xcc", 1, &dwRead)) {
					LOG("写入内存失败");
					m_ConditionStep = false;
					return dwCode;
				}
				m_ConditionStep = false;
				return dwCode;
		}

	}


	showDisasm(m_process, record.ExceptionAddress, 20);

	//需要用到DR6 DR7 寄存器,还有Dr0
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(m_Thread, &ct))
	{
		printf("获取线程环境失败\n");
	}

	// 因为触发异常后的地址可能不是硬件断点地址
	DBG_REG6 * pDR6 = (DBG_REG6*)&ct.Dr6;
	DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;

	SIZE_T addr = 0;

	if (pDR6->B0)						  //DR0导致中断
	{
		addr = ct.Dr0;
		//pDr7->L0 = 0;
	}
	else if (pDR6->B1)				//DR1导致中断
	{
		addr = ct.Dr1;
		//pDr7->L1 = 0;
	}
	else if (pDR6->B2)				//DR2导致中断
	{
		addr = ct.Dr2;
		//pDr7->L2 = 0;
	}
	else if (pDR6->B3)				//DR3导致中断
	{
		addr = ct.Dr3;
		//pDr7->L3 = 0;
	}
	m_bpAbout.RemoveBP_HARD(m_Thread, addr, false);
	
	
	// 接收用户输入
	userInput(record);

	return dwCode;
}

DWORD CmyDebug::OnExceptionMem(DEBUG_EVENT & Exception)
{
	printf("内存异常事件\n");
	DWORD dwCode = DBG_CONTINUE;

	// 遍历内存断点数组
	std::vector<Cbp_About::BP_MEM>::iterator iterMem;
	for (iterMem = m_bpAbout.m_Vec_Mem.begin(); iterMem != m_bpAbout.m_Vec_Mem.end(); )
	{
		// 判断触发内存访问异常的位置是否在设置的断点页内， ExceptionInformation第二个元素表示发生异常的地址
		SIZE_T ExceptionAddr = (SIZE_T)Exception.u.Exception.ExceptionRecord.ExceptionInformation[1];
		// 下断地址所在页的起始地址 = 下断地址 - 下断地址页对齐取余
		SIZE_T addrStart = iterMem->address - (iterMem->address % 0x1000);
		// 下断地址所在页的页末地址 = 页起始地址 + 页大小
		SIZE_T addrEnd = addrStart + 0xFFF;

		// 如果触发异常地址在所下断点页区域的话， 就得设单步一字节一字节跑直到下断地址了
		if (ExceptionAddr >= addrStart && ExceptionAddr <= addrEnd)
		{
			// 先恢复内存属性
			DWORD dwOldProtect = 0;
			VirtualProtectEx(m_process, (LPVOID)(iterMem->address), 1, iterMem->dwOldAttri, &dwOldProtect);

			// 然后设置单步断点
			m_bpAbout.SetBP_TF(m_Thread);

			// 将判断是否是内存断点引起的单步标志置 true
			m_MemStep = true;

			// 判断是否命中内存断点
			if (ExceptionAddr == iterMem->address)
			{
				
				// 判断是否是一次性内存断点
				if (iterMem->delFlag)
				{
					iterMem = m_bpAbout.m_Vec_Mem.erase(iterMem);
					// 如果命中就去掉刚刚设的单步断点
					m_bpAbout.RemoveBP_TF(m_Thread);
				}
				else
				{
					iterMem++;
				}
				// 命中断点则显示反汇编并接管到用户输入
				showDisasm(m_process, (LPVOID)ExceptionAddr, 20);    // 正常来讲应该反汇编线程的
				userInput(Exception.u.Exception.ExceptionRecord);
				
				return dwCode;
			}
			else
			{
				iterMem++;
			}
		}
		else
		{
			iterMem++;
		}
	}

	return dwCode;
}

void CmyDebug::ShowRegister()
{
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(m_Thread, &ct))
	{
		LOG("获取线程环境块失败");
		return;
	}
	WriteChar(13, 2, "EAX  ", (int)ct.Eax, F_H_GREEN);
	WriteChar(13, 3, "ECX  ", (int)ct.Ecx, F_H_GREEN);
	WriteChar(13, 4, "EDX  ", ct.Edx, F_H_GREEN);
	WriteChar(13, 5, "EBX  ", ct.Ebx, F_H_GREEN);
	WriteChar(13, 6, "ESP  ", ct.Esp, F_H_GREEN);
	WriteChar(13, 7, "EBP  ", ct.Ebp, F_H_GREEN);
	WriteChar(13, 8, "ESI  ", ct.Esi, F_H_GREEN);
	WriteChar(13, 9, "EDI  ", ct.Edi, F_H_GREEN);
	WriteChar(13, 11, "EIP  ",ct.Eip, F_H_GREEN);
	WriteChar(24, 4, "CS   ", ct.SegCs, F_H_YELLOW);
	WriteChar(24, 5, "SS   ", ct.SegSs, F_H_YELLOW);
	WriteChar(24, 6, "DS   ", ct.SegDs, F_H_YELLOW);
	WriteChar(24, 7, "ES   ", ct.SegFs, F_H_YELLOW);
	WriteChar(24, 8, "FS   ", ct.SegGs, F_H_YELLOW);
}

void CmyDebug::ShowStack()
{
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(m_Thread, &ct))
	{
		printf("获取线程环境失败");
		return;
	}

	BYTE buff[512];
	DWORD dwRead = 0;

	ReadProcessMemory(m_process, (LPVOID)ct.Esp, buff, 512, &dwRead);

	for (int i = 0; i < 10; i++)
	{
		WriteChar(35, 2 + i, "", ((DWORD*)buff)[i], F_H_YELLOW);
	}
}

SIZE_T CmyDebug::GetSymFuncName(SIZE_T Address, CString & strName)
{
	SymInitialize(m_process, NULL, TRUE);
// 	if (!SymInitialize(m_process, NULL, TRUE))
// 	{
// 		printf("获取调试符号出错\n");
// 	}
	DWORD64 dwDisplacement = 0;
	char    buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;         //(2000)

	// 根据地址获取符号信息
	if (!SymFromAddr(m_process, Address, &dwDisplacement, pSymbol))
	{
		return false;
	}
	strName.Format(L"%S", pSymbol->Name);
	return SIZE_T();
}

void CmyDebug::WriteChar(int x, int y, char * pszChar, int _number, WORD nColor)
{
		//获取当前光标位置，准备设置回去
		CONSOLE_SCREEN_BUFFER_INFO  rea = { 0 };
		GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &rea);

		CONSOLE_CURSOR_INFO Cci = { 1, false };			//光标属性结构
		SetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE), &Cci);
		COORD loc = { x * 2, y };
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), nColor);
		SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), loc);
		printf("%s", pszChar);
		printf("%08X", _number);

		//设置回去光标和颜色
		loc.X = rea.dwCursorPosition.X;
		loc.Y = rea.dwCursorPosition.Y;
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), F_H_WHITE);
		SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), loc);
}





void CmyDebug::TraverseModule(DWORD PID)
{
	//创建快照
	HANDLE hThreadSnap = 0;
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return;

	//结构体4
	MODULEENTRY32 stcPe32 = { sizeof(MODULEENTRY32) };

	//传入快照句柄 与 进程结构体
	Module32First(hThreadSnap, &stcPe32);

	printf("模块名	                 |	模块大小	|	模块基址	|	模块路径\n");
	do
	{
		wprintf(L"%-23s	 |	", stcPe32.szModule);
		wprintf(L"%08X	|	", stcPe32.modBaseSize);
		printf("%08X	|	", stcPe32.modBaseAddr);
		wprintf(L"%s\n", stcPe32.szExePath);

	} while (Module32Next(hThreadSnap, &stcPe32));
}

void CmyDebug::Dump(char * Name, char * path)
{
	HANDLE hFile = CreateFile(L"备份123.exe", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return;
	}

	IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)m_pBuff;
	IMAGE_NT_HEADERS* pNtHdr = (IMAGE_NT_HEADERS*)((ULONG_PTR)m_pBuff + pDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER* pOptHdr = &(pNtHdr->OptionalHeader);		//取地址问题
	IMAGE_DATA_DIRECTORY* pDataDir = pOptHdr->DataDirectory;		  //这里不用取

	//pDataDir[9].VirtualAddress = 0;
	//pDataDir[9].Size = 0;

	//写回文件
	DWORD dwBytesWrite = 0;
	WriteFile(hFile, m_pBuff, m_Size, &dwBytesWrite, NULL);

	//CloseHandle(m_hfile);

}

SIZE_T CmyDebug::ModuleToAddr(TCHAR * _Name, DWORD _PID)
{
	//创建快照
	HANDLE hThreadSnap = 0;
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, _PID);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return 0;

	//结构体4
	MODULEENTRY32 stcPe32 = { sizeof(MODULEENTRY32) };

	//传入快照句柄 与 进程结构体
	Module32First(hThreadSnap, &stcPe32);

	do
	{
		if (!_wcsicmp(_Name, stcPe32.szModule))
			return (SIZE_T)stcPe32.modBaseAddr;

	} while (Module32Next(hThreadSnap, &stcPe32));
}

void CmyDebug::PaserExportTable(SIZE_T _Address)
{
	SIZE_T toAddress = _Address;

	//找到DOS头的NT头偏移
	BYTE  buff[sizeof(IMAGE_DOS_HEADER)];
	DWORD dwRead = 0;
	DWORD dwOldProtect = 0;	//存储原本页面属性					//修改页面属性
	VirtualProtectEx(m_process, (LPVOID)(toAddress), sizeof(IMAGE_DOS_HEADER), PAGE_READWRITE, &dwOldProtect);
	ReadProcessMemory(m_process, (LPVOID)toAddress, buff, sizeof(IMAGE_DOS_HEADER), &dwRead);
	VirtualProtectEx(m_process, (LPVOID)(toAddress), sizeof(IMAGE_DOS_HEADER), dwOldProtect, &dwOldProtect);

	IMAGE_DOS_HEADER* DosHed = (IMAGE_DOS_HEADER*)buff;
	DosHed->e_lfanew;

	//找到NT头 的扩展头
	(ULONG_PTR)toAddress += DosHed->e_lfanew;
	(ULONG_PTR)toAddress += 4;
	VirtualProtectEx(m_process, (LPVOID)(toAddress), sizeof(IMAGE_FILE_HEADER), PAGE_READWRITE, &dwOldProtect);
	ReadProcessMemory(m_process, (LPVOID)toAddress, buff, sizeof(IMAGE_FILE_HEADER), &dwRead);
	VirtualProtectEx(m_process, (LPVOID)(toAddress), sizeof(IMAGE_FILE_HEADER), dwOldProtect, &dwOldProtect);

	IMAGE_FILE_HEADER* FileHed = (IMAGE_FILE_HEADER*)buff;
	FileHed->SizeOfOptionalHeader;

	toAddress += sizeof(IMAGE_FILE_HEADER);			//得到扩展头地址

	char* optbuff[sizeof(IMAGE_OPTIONAL_HEADER)] = {};		//扩展头一般大小为E0
	VirtualProtectEx(m_process, (LPVOID)(toAddress), 0xE0, PAGE_READWRITE, &dwOldProtect);
	ReadProcessMemory(m_process, (LPVOID)toAddress, optbuff, 0xE0, &dwRead);
	VirtualProtectEx(m_process, (LPVOID)(toAddress), 0xE0, dwOldProtect, &dwOldProtect);

	//0x00CA595A 处有未经处理的异常(在 ConsoleApplication2.exe 中):  0xC0000005:  读取位置 0x00001008 时发生访问冲突。
	//扩展头比DOS头大,越界

	IMAGE_OPTIONAL_HEADER* OptHed = (IMAGE_OPTIONAL_HEADER*)optbuff;

	//找到NT头的数据目录表里的导出表
	OptHed->DataDirectory[0];

	//默认加载基址 加 RVA 等于导出表的偏移
	toAddress = (ULONG_PTR)_Address + (ULONG_PTR)OptHed->DataDirectory[0].VirtualAddress;

	optbuff;		//导出表的大小为40个字节
	VirtualProtectEx(m_process, (LPVOID)(toAddress), 40, PAGE_READWRITE, &dwOldProtect);
	ReadProcessMemory(m_process, (LPVOID)toAddress, optbuff, 40, &dwRead);
	VirtualProtectEx(m_process, (LPVOID)(toAddress), 40, dwOldProtect, &dwOldProtect);

	//导出表
	IMAGE_EXPORT_DIRECTORY* EXPORTTable = (IMAGE_EXPORT_DIRECTORY*)optbuff;


	//先把函数地址,函数序号,函数名 分别用三个数组 存起来,然后下面打印输出
	DWORD* FunionAddressTable = new DWORD[EXPORTTable->NumberOfFunctions];
	WORD* BaseTable = new WORD[EXPORTTable->NumberOfNames];
	char** FunionNameTable = new char*[EXPORTTable->NumberOfNames];

	//先搞函数地址
	DWORD FunionAddress = (ULONG_PTR)EXPORTTable->AddressOfFunctions + (ULONG_PTR)_Address;
	for (int i = 0; i < EXPORTTable->NumberOfFunctions; i++)
	{
		VirtualProtectEx(m_process, (LPVOID)((DWORD*)FunionAddress + i), 4, PAGE_READWRITE, &dwOldProtect);
		ReadProcessMemory(m_process, (LPVOID)((DWORD*)FunionAddress + i), &(FunionAddressTable[i]), 4, &dwRead);
		VirtualProtectEx(m_process, (LPVOID)((DWORD*)FunionAddress + i), 4, dwOldProtect, &dwOldProtect);
	}

	//再搞序号,和名字
	DWORD FunionOrd = (ULONG_PTR)EXPORTTable->AddressOfNameOrdinals + (ULONG_PTR)_Address;
	DWORD FuntionName = (ULONG_PTR)EXPORTTable->AddressOfNames + (ULONG_PTR)_Address;
	for (int i = 0; i < EXPORTTable->NumberOfNames; i++)
	{
		VirtualProtectEx(m_process, (LPVOID)((DWORD*)FunionOrd + i), 2, PAGE_READWRITE, &dwOldProtect);
		ReadProcessMemory(m_process, (LPVOID)((DWORD*)FunionOrd + i), &((BaseTable)[i]), 2, &dwRead);
		VirtualProtectEx(m_process, (LPVOID)((DWORD*)FunionOrd + i), 2, dwOldProtect, &dwOldProtect);

		//函数名比较麻烦
		//先得到函数地址RVA
		DWORD FuntionRVA = 0;
		VirtualProtectEx(m_process, (LPVOID)((DWORD*)FuntionName + i), 4, PAGE_READWRITE, &dwOldProtect);
		ReadProcessMemory(m_process, (LPVOID)((DWORD*)FuntionName + i), &FuntionRVA, 4, &dwRead);
		VirtualProtectEx(m_process, (LPVOID)((DWORD*)FuntionName + i), 4, dwOldProtect, &dwOldProtect);

		//根据RVA 读名字,读50个字节,有'\0',可放心
		//读出来的地址需要加上默认基址
		FuntionRVA += (ULONG_PTR)_Address;
		char* cName = new char[50]();
		VirtualProtectEx(m_process, (LPVOID)((DWORD*)FuntionRVA + i), 50, PAGE_READWRITE, &dwOldProtect);
		ReadProcessMemory(m_process, (LPVOID)((DWORD*)FuntionRVA + i), cName, 50, &dwRead);
		VirtualProtectEx(m_process, (LPVOID)((DWORD*)FuntionRVA + i), 50, dwOldProtect, &dwOldProtect);
		FunionNameTable[i] = cName;
	}

	printf("函数地址	|	函数序号	|	函数名\n");

	for (int i = 0; i < EXPORTTable->NumberOfFunctions; i++)
	{
		//根据三个数组,和 输出表的规律
		//打印函数地址		//打印序号

		printf("%08X	|	", FunionAddressTable[i]);
		printf("%08X	|	", i);

		//遍历序号表,打印函数名
		for (int j = 0; j < EXPORTTable->NumberOfNames; j++)
		{
			if (BaseTable[j] == i)
			{
				printf("%s", FunionNameTable[j]);
			}
		}

		printf("\n");
	}

	delete FunionAddressTable;
	FunionAddressTable = NULL;
	delete BaseTable;
	BaseTable = NULL;
	//delete 函数名表
	delete[]FunionNameTable;
}

void CmyDebug::PaserImportTable(SIZE_T _Address)
{
	SIZE_T toAddress = _Address;

	//找到DOS头的NT头偏移
	BYTE  buff[sizeof(IMAGE_DOS_HEADER)];
	DWORD dwRead = 0;
	DWORD dwOldProtect = 0;	//存储原本页面属性					//修改页面属性
	VirtualProtectEx(m_process, (LPVOID)(toAddress), sizeof(IMAGE_DOS_HEADER), PAGE_READWRITE, &dwOldProtect);
	ReadProcessMemory(m_process, (LPVOID)toAddress, buff, sizeof(IMAGE_DOS_HEADER), &dwRead);
	VirtualProtectEx(m_process, (LPVOID)(toAddress), sizeof(IMAGE_DOS_HEADER), dwOldProtect, &dwOldProtect);

	IMAGE_DOS_HEADER* DosHed = (IMAGE_DOS_HEADER*)buff;
	DosHed->e_lfanew;

	//找到NT头 的扩展头
	(ULONG_PTR)toAddress += DosHed->e_lfanew;
	(ULONG_PTR)toAddress += 4;
	VirtualProtectEx(m_process, (LPVOID)(toAddress), sizeof(IMAGE_FILE_HEADER), PAGE_READWRITE, &dwOldProtect);
	ReadProcessMemory(m_process, (LPVOID)toAddress, buff, sizeof(IMAGE_FILE_HEADER), &dwRead);
	VirtualProtectEx(m_process, (LPVOID)(toAddress), sizeof(IMAGE_FILE_HEADER), dwOldProtect, &dwOldProtect);

	IMAGE_FILE_HEADER* FileHed = (IMAGE_FILE_HEADER*)buff;
	FileHed->SizeOfOptionalHeader;

	toAddress += sizeof(IMAGE_FILE_HEADER);			//得到扩展头地址

	char* optbuff[sizeof(IMAGE_OPTIONAL_HEADER)] = {};		//扩展头一般大小为E0
	VirtualProtectEx(m_process, (LPVOID)(toAddress), 0xE0, PAGE_READWRITE, &dwOldProtect);
	ReadProcessMemory(m_process, (LPVOID)toAddress, optbuff, 0xE0, &dwRead);
	VirtualProtectEx(m_process, (LPVOID)(toAddress), 0xE0, dwOldProtect, &dwOldProtect);

	//0x00CA595A 处有未经处理的异常(在 ConsoleApplication2.exe 中):  0xC0000005:  读取位置 0x00001008 时发生访问冲突。
	//扩展头比DOS头大,越界

	IMAGE_OPTIONAL_HEADER* OptHed = (IMAGE_OPTIONAL_HEADER*)optbuff;

	//找到NT头的数据目录表里的导入表
	OptHed->DataDirectory[1];

	//默认加载基址 加 RVA 等于导入表的偏移
	toAddress = (ULONG_PTR)_Address + (ULONG_PTR)OptHed->DataDirectory[1].VirtualAddress;

	IMAGE_IMPORT_DESCRIPTOR* IMPORTTable = 0;

	//可能有多个导入表
	//导入表的首地址
	do
	{
		//直接读取导入表内存
		char* Imabuff[sizeof(IMAGE_IMPORT_DESCRIPTOR)] = {};
		VirtualProtectEx(m_process, (LPVOID)(toAddress), sizeof(IMAGE_IMPORT_DESCRIPTOR), PAGE_READWRITE, &dwOldProtect);
		ReadProcessMemory(m_process, (LPVOID)toAddress, Imabuff, sizeof(IMAGE_IMPORT_DESCRIPTOR), &dwRead);
		VirtualProtectEx(m_process, (LPVOID)(toAddress), sizeof(IMAGE_IMPORT_DESCRIPTOR), dwOldProtect, &dwOldProtect);

		//由于while条件需要，所以在外部定义
		IMPORTTable = (IMAGE_IMPORT_DESCRIPTOR*)Imabuff;

		if (!IMPORTTable->Name)
			break;

		//DLL的VA
		DWORD NameAddress = (ULONG_PTR)IMPORTTable->Name + (ULONG_PTR)_Address;

		//打印名字			//解析成功
		char DllName[50] = {};
		VirtualProtectEx(m_process, (LPVOID)(NameAddress), 50, PAGE_READWRITE, &dwOldProtect);
		ReadProcessMemory(m_process, (LPVOID)NameAddress, DllName, 50, &dwRead);
		VirtualProtectEx(m_process, (LPVOID)(NameAddress), 50, dwOldProtect, &dwOldProtect);
		//printf("DLL名：%s\n\n", DllName);
		//
		//搞一个有颜色的DLL名
		//获取当前光标位置，准备设置回去
		CONSOLE_SCREEN_BUFFER_INFO  rea = { 0 };
		GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &rea);

		CONSOLE_CURSOR_INFO Cci = { 1, false };			//光标属性结构
		SetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE), &Cci);
		COORD loc = { rea.dwCursorPosition.X + 15 , rea.dwCursorPosition.Y };
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), F_H_GREEN);
		SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), loc);
		printf("%s\n\n", DllName);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), F_H_WHITE);



		//IAT地址
		IMAGE_THUNK_DATA * ThunkAddress = (IMAGE_THUNK_DATA*)((ULONG_PTR)IMPORTTable->FirstThunk + (ULONG_PTR)_Address);
		//INT地址
		IMAGE_THUNK_DATA * INTAddress = (IMAGE_THUNK_DATA*)((ULONG_PTR)IMPORTTable->OriginalFirstThunk + (ULONG_PTR)_Address);
		do
		{

			//解析IAT，得到地址,再解析INT，得出序号和名字，

			//读出来
			IMAGE_THUNK_DATA  ThunkDataAddress = {};
			VirtualProtectEx(m_process, (LPVOID)(ThunkAddress), sizeof(IMAGE_THUNK_DATA), PAGE_READWRITE, &dwOldProtect);
			ReadProcessMemory(m_process, (LPVOID)ThunkAddress, &ThunkDataAddress, sizeof(IMAGE_THUNK_DATA), &dwRead);
			VirtualProtectEx(m_process, (LPVOID)(ThunkAddress), sizeof(IMAGE_THUNK_DATA), dwOldProtect, &dwOldProtect);

			//地址为空，结构体为零时跳出循环
			if (!ThunkDataAddress.u1.Function)
				break;

			//打印地址
			printf("%08X	|	", ThunkDataAddress.u1.Function);



			///先读出
			//序号、名字
			//得到第一个IMAGE_THUNK_DATA结构体地址		//上面给了
			//读出来
			IMAGE_THUNK_DATA  ThunkData = {};
			VirtualProtectEx(m_process, (LPVOID)(INTAddress), sizeof(IMAGE_THUNK_DATA), PAGE_READWRITE, &dwOldProtect);
			ReadProcessMemory(m_process, (LPVOID)INTAddress, &ThunkData, sizeof(IMAGE_THUNK_DATA), &dwRead);
			VirtualProtectEx(m_process, (LPVOID)(INTAddress), sizeof(IMAGE_THUNK_DATA), dwOldProtect, &dwOldProtect);

			//如果是序号导入的
			if (IMAGE_SNAP_BY_ORDINAL(ThunkData.u1.Ordinal))
			{
				//直接打印序号
				printf("%08X	|	", LOWORD(ThunkData.u1.Ordinal));
			}
			else
			{
				//找到序号 函数名，打印
				//得到IMAGE_IMPORT_BY_NAME结构体
				IMAGE_IMPORT_BY_NAME * ImportByName = (IMAGE_IMPORT_BY_NAME*)((ULONG_PTR)ThunkData.u1.AddressOfData + (ULONG_PTR)_Address);

				//再读出来						//IMAGE_IMPORT_BY_NAME不固定大小，但没事，得到首地址直接读
				IMAGE_IMPORT_BY_NAME  byName = {};
				VirtualProtectEx(m_process, (LPVOID)(ImportByName), sizeof(IMAGE_IMPORT_BY_NAME), PAGE_READWRITE, &dwOldProtect);
				ReadProcessMemory(m_process, (LPVOID)ImportByName, &byName, sizeof(IMAGE_IMPORT_BY_NAME), &dwRead);
				VirtualProtectEx(m_process, (LPVOID)(ImportByName), sizeof(IMAGE_IMPORT_BY_NAME), dwOldProtect, &dwOldProtect);

				//打印序号
				printf("%08X	|	", byName.Hint);

				//读出函数名
				char _FuntionName[50] = {};
				VirtualProtectEx(m_process, (LPVOID)(&ImportByName->Name), 50, PAGE_READWRITE, &dwOldProtect);
				ReadProcessMemory(m_process, (LPVOID)&ImportByName->Name, _FuntionName, 50, &dwRead);
				VirtualProtectEx(m_process, (LPVOID)(&ImportByName->Name), 50, dwOldProtect, &dwOldProtect);

				//打印函数名
				printf("%s	|	", _FuntionName);
			}

			printf("\n");
			//再来一个大循环
			ThunkAddress++;
			INTAddress++;
		} while (1);


		printf("\n\n\n");

		(ULONG_PTR)toAddress += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		//判断是否为空
	} while (1);		//结构体为零时结束			//while 条件会改变变量(NameAddress)的值)
}











