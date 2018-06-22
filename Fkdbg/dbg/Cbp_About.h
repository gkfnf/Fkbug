#pragma once
#include "Cdbg_Info.h"
#include <vector>
#include "debugRegisters.h"

#define BP_HARD_EXEC     0 
#define BP_HARD_WR			 1
#define BP_HARD_RWDATA   3
#define K1_BYTE          0
#define K2_BYTE          1
#define K4_BYTE          3       


// 断点相关类
class Cbp_About
{
public:
	Cbp_About();
	~Cbp_About();

// 单步断点相关:
	void SetBP_TF(HANDLE hTrhead);
	void RemoveBP_TF(HANDLE hThread);

        

// 软件断点相关:
	typedef struct _BP_INT3 {
		BOOL   delFlag;        // 删除标志:一次性断点为 true
		BYTE   oldbyte;        // 原来的一字节内容
		SIZE_T address;        // 断点地址
	}BP_INT3;
	std::vector <BP_INT3> m_Vec_INT3;
	BOOL SetBP_INT3(HANDLE hProc, SIZE_T address, bool delflag);


// 硬件断点相关
	typedef struct _BP_HARD {
		BOOL   delFlag;        // 删除标志:一次性断点为 true
		SIZE_T address;        // 断点地址
		DWORD Type;						 // 断点类型
		DWORD Len;             // 断点对齐粒度
	}BP_HARD;

	std::vector<BP_HARD> m_Vec_HARD;

	BOOL SetBP_HARD(HANDLE hThread, ULONG_PTR uAddress, DWORD Type, DWORD Len, BOOL delflag);
	void RemoveBP_HARD(HANDLE hThread, SIZE_T Address, bool bc);    

// 内存断点相关
	typedef struct _BP_MEM {
		BOOL   delFlag;          // 删除标志:一次性断点为 true
		SIZE_T address;          // 断点地址
		DWORD  dwOldAttri;       // 内存断点原来的内存分页属性
	}BP_MEM;
	std::vector<BP_MEM> m_Vec_Mem;
	void  SetBP_MEM(HANDLE hProcess, SIZE_T Address, BOOL defflag);


// 条件断点相关
//寄存器类型枚举
	enum Eregister
	{
		e_eax,
		e_ecx,
		e_edx,
		e_ebx,
		e_esp,
		e_ebp,
		e_esi,
		e_edi,
		e_ecs,
		e_ess,
		e_eds,
		e_ees,
		e_efs,
		e_egs
	};


	typedef struct _BP_CONDITION {
		BYTE   oldbyte;          // 原来的一字节内容
		SIZE_T address;          // 断点地址
		BOOL   ConditionWay;     // 条件方式
		DWORD  Times;            // 条件断点命中次数
		DWORD  EndTimes;         // 条件断点条件次数
		DWORD  EndValue;         // 条件断点条件寄存器值
		Eregister Reg;           // 条件断点需要判断的寄存器
	}BP_CONDITION;



	std::vector<BP_CONDITION> m_Vec_Condition;

	BOOL SetBP_Condition(HANDLE hProcess, SIZE_T Address, BOOL ConditionWay, DWORD EndTimes, DWORD EndValue, Eregister Reg);

};

