#pragma once
#include <windows.h>
#include "disasm.h"


typedef union {
	DWORD I32;
	WORD I16;
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
		};
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

	// 新增：CPU 状态标记
	bool Halted;
}CPU_Context;

int runcpu(CPU_Context* p, int step);

// 修改 ExecuteInstruction 返回 bool
// 返回 true: 表示指令发生了跳转 (EIP 已被修改)，调用者不需要再加 instr_len
// 返回 false: 普通指令，调用者需要执行 EIP += instr_len
bool ExecuteInstruction(CPU_Context* ctx, DecodeContext* d_ctx);

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
void Exec_MOV_Generic(CPU_Context* ctx, DecodeContext* d_ctx);

// 定义操作类型，用于标志位计算
typedef enum {
	ALU_ADD,
	ALU_OR,
	ALU_ADC,
	ALU_SBB,
	ALU_AND,
	ALU_SUB,
	ALU_XOR,
	ALU_CMP,
	ALU_INC,
	ALU_DEC
} ALU_Op;
// 计算奇偶性 (Parity Flag) - 仅检查低8位
// Intel 手册规定的硬件行为：无论你进行的是 8 位、16 位、32 位还是 64 位运算，奇偶校验位（PF）始终只关注结果的最低 8 位（LSB）。
int CalcPF(uint8_t res);
// 核心：根据运算结果和操作数更新 EFLAGS
// res: 运算结果
// dest: 目的操作数 (运算前的值)
// src: 源操作数
// size: 操作数大小 (8, 16, 32)
// op: 运算类型
//目前实现了ADD和SUB的EFLAGS更新，其他的可以参考着实现
void UpdateEFLAGS(CPU_Context* ctx, uint32_t res, uint32_t dest, uint32_t src, int size, ALU_Op op);

//为了避免给 ADD、SUB、CMP 各写一个函数，我们实现一个通用的 ALU 执行函数。
// 通用算术逻辑执行函数
// op_code: 具体的 ALU 操作码枚举 (ADD, SUB, AND...)
// is_compare: 如果为 true (如 CMP, TEST)，不写回结果
void Exec_ALU_Generic(CPU_Context* ctx, DecodeContext* d_ctx, ALU_Op op, bool is_compare);
// 辅助函数：获取操作数的实际位宽 (8, 16, 32)
// 用于确保 ALU 标志位计算正确
int GetOperandBitSize(CPU_Context* ctx, DecodeContext* d_ctx, OperandType type);
// 处理 Group 1 指令 (0x80-0x83: ADD/OR/ADC/SBB/AND/SUB/XOR/CMP immediate)
void Exec_Group1(CPU_Context* ctx, DecodeContext* d_ctx);
// PUSH r32 / imm32 / imm8
void Exec_PUSH(CPU_Context* ctx, DecodeContext* d_ctx);
// POP r32
void Exec_POP(CPU_Context* ctx, DecodeContext* d_ctx);
// 检查条件跳转是否成立 (Jcc)
// condition_code: 指令 Opcode 的低 4 位 (0x70-0x7F 或 0x80-0x8F 的低位),还可以处理类似的逻辑，比如CMOV,SETcc等
bool CheckCondition(CPU_Context* ctx, uint8_t condition_code);
// 处理相对跳转 (JMP, Jcc, CALL)
// 返回 true 表示跳转发生
bool Exec_Branch(CPU_Context* ctx, DecodeContext* d_ctx, bool is_conditional);
// 处理 CALL (相对调用)
bool Exec_CALL(CPU_Context* ctx, DecodeContext* d_ctx);
// 处理 RET与带参数 (返回)
bool Exec_RET(CPU_Context* ctx, DecodeContext* d_ctx);
//处理DEC
void Exec_DEC(CPU_Context* ctx, DecodeContext* d_ctx);
//处理INC
void Exec_INC(CPU_Context* ctx, DecodeContext* d_ctx);

// 辅助：仅更新逻辑标志位 (ZF, SF, PF)
void UpdateLogicFlags(CPU_Context* ctx, uint32_t res, int size);
//处理Group2指令：SHL, SHR, SAR(移位) 和 ROL, ROR, RCL, RCR(循环移位)。
void Exec_Group2(CPU_Context* ctx, DecodeContext* d_ctx);

// 辅助：获取 Group 3 的源操作数 (Multiplier / Divisor)
uint32_t GetGroup3Source(CPU_Context* ctx, DecodeContext* d_ctx);
// 写入 Group 3 结果
void SetGroup3Dest(CPU_Context* ctx, DecodeContext* d_ctx, uint32_t val);
// 处理 Group 3 指令 (MUL, IMUL, DIV, IDIV)
void Exec_Group3(CPU_Context* ctx, DecodeContext* d_ctx);
//内存读辅助函数,返回读取的值
uint32_t MemRead(uint32_t addr, int byte_len);
//内存写辅助函数
void MemWrite(uint32_t addr,uint32_t val, int byte_len);

// 执行串操作指令
void Exec_StringOp(CPU_Context* ctx, DecodeContext* d_ctx);
//rep/repne 前缀处理串操作指令
bool Exec_REP_StringOp(CPU_Context* ctx, DecodeContext* d_ctx);

// 处理 LEA 指令 (0x8D)
void Exec_LEA(CPU_Context* ctx, DecodeContext* d_ctx);

// 辅助：将 EFLAGS 结构体打包成 32位 整数
uint32_t PackEFLAGS(CPU_Context* ctx);
// 辅助：从 32位 整数解包到 EFLAGS
void UnpackEFLAGS(CPU_Context* ctx, uint32_t val);
//XCHG(0x90-0x97)
void Exec_XCHG(CPU_Context* ctx, DecodeContext* d_ctx);
// PUSHF (0x9C)
void Exec_PUSHF(CPU_Context* ctx);
// POPF (0x9D)
void Exec_POPF(CPU_Context* ctx);

// LEAVE (0xC9): 恢复栈帧
// 等价于: MOV ESP, EBP; POP EBP;
void Exec_LEAVE(CPU_Context* ctx);
// ENTER (0xC8): 建立栈帧
// 指令格式: ENTER size(16), level(8)
void Exec_ENTER(CPU_Context* ctx, DecodeContext* d_ctx);

// 处理 Group 4 (0xFE): 只有 INC Eb / DEC Eb
void Exec_Group4(CPU_Context* ctx, DecodeContext* d_ctx);
// 处理 Group 5 (0xFF): INC/DEC/CALL/JMP/PUSH,返回1发生跳转，0未发生跳转
bool Exec_Group5(CPU_Context* ctx, DecodeContext* d_ctx);
// MOVZX: Zero Extend (零扩展)
// src_bits: 源操作数位数 (8 或 16)
void Exec_MOVZX(CPU_Context* ctx, DecodeContext* d_ctx, int src_bits);
// MOVSX: Sign Extend (符号扩展)
void Exec_MOVSX(CPU_Context* ctx, DecodeContext* d_ctx, int src_bits);
// SETcc Eb
void Exec_SETcc(CPU_Context* ctx, DecodeContext* d_ctx);
// CMOVcc Gv, Ev (0x0F 40 - 0x0F 4F)
// 根据条件传送数据。条件码由 Opcode 低 4 位决定。
void Exec_CMOVcc(CPU_Context* ctx, DecodeContext* d_ctx);
// IMUL Gv, Ev (0x0F AF)
// 有符号乘法，双操作数版本：Dest = Dest * Src
void Exec_IMUL_2_Op(CPU_Context* ctx, DecodeContext* d_ctx);

// 处理 0x98 (CBW/CWDE) 和 0x99 (CWD/CDQ)
void Exec_SignExtend(CPU_Context* ctx, DecodeContext* d_ctx);

// 处理 INT n (0xCD) 和 INT 3 (0xCC)
// 我们将在这里通过 HLE (高层模拟) 拦截系统调用
void Exec_INT(CPU_Context* ctx, DecodeContext* d_ctx);
// LOOP 指令 (0xE0-E2), 返回0未发生跳转，1发生跳转
bool Exec_LOOP(CPU_Context* ctx, DecodeContext* d_ctx);
