#pragma once
#include <windows.h>
#include "disasm.h"


typedef union {
	DWORD I32;
	DWORD I16;
	struct {
		BYTE L;
		BYTE H;
	}I8;
}REG32;

typedef struct {
	//通用寄存器
	union {
		REG32 GPR[8];
		struct {
			REG32 EAX;
			REG32 ECX;
			REG32 EDX;
			REG32 EBX;
			REG32 ESP;
			REG32 EBP;
			REG32 ESI;
			REG32 EDI;
		};
	};
	//指令指针
	DWORD EIP;
	union {
		DWORD Value;           // 整体读写 -> ctx.EFLAGS.Value
		struct {               // 按位访问 -> ctx.EFLAGS.Bits.ZF
			DWORD CF : 1;
			DWORD : 1;     // 保留位
			DWORD PF : 1;
			DWORD : 1;
			DWORD AF : 1;
			DWORD : 1;
			DWORD ZF : 1;
			DWORD SF : 1;
			DWORD TF : 1;
			DWORD IF : 1;
			DWORD DF : 1;
			DWORD OF : 1;
			DWORD IOPL : 2;
			DWORD NT : 1;
			DWORD : 15;
		} Bits;
	} EFLAGS;
	//段寄存器
	union {
		WORD seg[6];
		struct {
			WORD ES;
			WORD CS;
			WORD SS;
			WORD DS;
			WORD FS;
			WORD GS;
		};
	};

}CPU_Context;

// 前置声明：执行分发函数 (将在任务2中实现)
void ExecuteInstruction(CPU_Context* ctx, DecodeContext* d_ctx);

void Exec_NOP(CPU_Context* ctx);

// 辅助函数：根据索引和大小读取通用寄存器
// ctx: CPU上下文
// reg_index: 寄存器索引 (0-7)
// size: 大小 (8, 16, 32)
uint32_t ReadGPR(CPU_Context* ctx, int reg_index, int size);
// 辅助函数：写入通用寄存器
//0执行报错，1成功
bool WriteGPR(CPU_Context* ctx, int reg_index, int size, uint32_t value);
// 计算内存操作数的有效地址 (Effective Address)
// 返回值：宿主进程中的真实虚拟地址
uint32_t GetEffectiveAddress(CPU_Context* ctx, DecodeContext* d_ctx);
// 获取操作数的值
// op_idx: 0 (op1), 1 (op2), 2 (op3)
uint32_t GetOperandValue(CPU_Context* ctx, DecodeContext* d_ctx, int op_idx);
// 写入操作数的值
void SetOperandValue(CPU_Context* ctx, DecodeContext* d_ctx, int op_idx, uint32_t value);
// 处理 MOV r32, imm32 (0xB8 - 0xBF)
void Exec_MOV_Reg_Imm(CPU_Context* ctx, DecodeContext* d_ctx);