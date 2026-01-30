// x86-emulator_v1.0.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "TinyX86.h"
#include <stdio.h> // 用于printf调试


int runcpu(CPU_Context* p, int step)
{
	DecodeContext d_ctx;
	int instr_len = 0;
	for (int i = 0; i < step; i++) {
		// 1. 取指与解码 (Fetch & Decode)
		// 直接读取宿主内存地址 p->EIP
		instr_len = ParseInstuction((uint8_t*)p->EIP, p->EIP, &d_ctx);
		FormatInstruction((uint8_t*)p->EIP, &d_ctx);//可选，显示汇编指令，会消耗额外的cpu性能，适合调试时使用
		if (instr_len <= 0) {
			printf("Error: Decoding failed at EIP: 0x%08X\n", p->EIP);
			return -1;
		}
		// 2. 执行指令 (Execute)
		// 传递 instr_len 给执行函数，因为 JMP 需要基于 (EIP + len) 计算跳转目标
		bool jumped = ExecuteInstruction(p, &d_ctx);
		// 3. 更新 EIP 指向下一条指令
		// 仅当没有发生跳转时，才推进 EIP
		if (!jumped) p->EIP += instr_len;
		// 调试打印 (可选，用于观察 Sprint 1 效果)
		printf("[Trace] EIP=0x%08X | Instr: %s | Len: %d\n", p->EIP, d_ctx.asm_str, instr_len);

	}
	return 0;
}


// 执行分发器
bool ExecuteInstruction(CPU_Context* ctx, DecodeContext* d_ctx) {
	// 默认不跳转
	bool jumped = false;
	switch (d_ctx->opcode) {
		// --- Sprint 3 新增 ---
		// Group 1 (立即数运算)
		case 0x80: case 0x81: case 0x83:
			Exec_Group1(ctx, d_ctx); break;
			// 标准 ADD (Gv, Ev 等)
		case 0x00: case 0x01: case 0x02: case 0x03: case 0x04: case 0x05:
			Exec_ALU_Generic(ctx, d_ctx, ALU_ADD, false); break;
			//标准 OR
		case 0x08: case 0x09: case 0x0A: case 0x0B: case 0x0C: case 0x0D:
			Exec_ALU_Generic(ctx, d_ctx, ALU_OR, false); break;
			//标准ADC
		case 0x10: case 0x11: case 0x12: case 0x13: case 0x14: case 0x15:
			Exec_ALU_Generic(ctx, d_ctx, ALU_ADC, false); break;
			//标准SBB
		case 0x18: case 0x19: case 0x1A: case 0x1B: case 0x1C: case 0x1D:
			Exec_ALU_Generic(ctx, d_ctx, ALU_SBB, false); break;
			// 标准 AND
		case 0x20: case 0x21: case 0x22: case 0x23: case 0x24: case 0x25:
			Exec_ALU_Generic(ctx, d_ctx, ALU_AND, false); break;
			// 标准 SUB
		case 0x28: case 0x29: case 0x2A: case 0x2B: case 0x2C: case 0x2D:
			Exec_ALU_Generic(ctx, d_ctx, ALU_SUB, false); break;
			// 标准 CMP
		case 0x38: case 0x39: case 0x3A: case 0x3B: case 0x3C: case 0x3D:
			Exec_ALU_Generic(ctx, d_ctx, ALU_CMP, true); break;
		// --- INC / DEC ---
		case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47:
			Exec_INC(ctx, d_ctx); break;
		case 0x48: case 0x49: case 0x4A: case 0x4B: case 0x4C: case 0x4D: case 0x4E: case 0x4F:
			Exec_DEC(ctx, d_ctx);break;

		// --- PUSH / POP ---
		case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: // PUSH r32
		case 0x68: case 0x6A: // PUSH imm
		case 0x06: case 0x0E: case 0x16: case 0x1E: // PUSH Seg
			Exec_PUSH(ctx, d_ctx);
			break;
		case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F: // POP r32
		case 0x07: case 0x1F: // POP Seg
			Exec_POP(ctx, d_ctx);
			break;

			// --- JMP / CALL / RET ---
		case 0xE9: // JMP Jz (Near Jump 32)
		case 0xEB: // JMP Jb (Short Jump 8)
			jumped = Exec_Branch(ctx, d_ctx, false);
			break;

		case 0xE8: // CALL Jz
			jumped = Exec_CALL(ctx, d_ctx);
			break;

		case 0xC3: // RETN
		case 0xC2: // RETN Iw
			jumped = Exec_RET(ctx, d_ctx);
			break;

			// --- Jcc (条件跳转) ---
			// 0x70 - 0x7F (Short Jumps)
		case 0x70: case 0x71: case 0x72: case 0x73:
		case 0x74: case 0x75: case 0x76: case 0x77:
		case 0x78: case 0x79: case 0x7A: case 0x7B:
		case 0x7C: case 0x7D: case 0x7E: case 0x7F:
			jumped = Exec_Branch(ctx, d_ctx, true);
			break;

			// 0x0F 8x (Long Jumps) - 属于 Opcode 扩展，注意 disasm 是否处理了 two_byte_opcode
			// 如果是双字节码，switch(d_ctx->opcode) 可能只拿到了 0x8x (取决于你的 disasm 实现)
			// 根据你的 disasm.c 逻辑，is_two_byte_opcode 会被设置。
			// 如果 d_ctx->is_two_byte_opcode 为真，你需要在这里特判或者用两张 switch 表。
			// Sprint 4 简化起见，先假设我们只处理 0x7x 系列短跳转。

		case 0x90: break; // NOP

			// MOV (上一轮实现的)
		case 0x88: case 0x89: case 0x8A: case 0x8B:
		case 0xB0: case 0xB1: case 0xB2: case 0xB3:
		case 0xB4: case 0xB5: case 0xB6: case 0xB7:
		case 0xB8: case 0xB9: case 0xBA: case 0xBB:
		case 0xBC: case 0xBD: case 0xBE: case 0xBF:
		case 0xC6: case 0xC7: 
			Exec_MOV_Reg_Imm(ctx, d_ctx); break;// 建议改名为更通用的 Exec_MOV

		case 0xA0: // MOV AL, moffs8
			// 指令格式：A0 [offset32]
			// 注意：这里的 d_ctx->imm 应该是解码阶段读取到的 4 字节地址偏移
			ctx->GPR[0].I8.L = (uint8_t)MemRead(d_ctx->imm, 1);
			break;

		case 0xA1: // MOV EAX, moffs16/32
		{
			int size = (d_ctx->pfx_op_size == 0x66) ? 2 : 4;
			if (size == 2) ctx->GPR[0].I16 = (uint16_t)MemRead(d_ctx->imm, 2);
			else ctx->GPR[0].I32 = MemRead(d_ctx->imm, 4);
		}
		break;
		case 0xA2: // MOV moffs8, AL
			MemWrite(d_ctx->imm, ctx->GPR[0].I8.L, 1);
			break;
		case 0xA3: // MOV moffs16/32, EAX
		{
			int size = (d_ctx->pfx_op_size == 0x66) ? 2 : 4;
			if (size == 2) MemWrite(d_ctx->imm, ctx->GPR[0].I16, 2);
			else MemWrite(d_ctx->imm, ctx->GPR[0].I32, 4);
		}
		break;

			//sprint6:字符串操作
		case 0xA4: case 0xA5: // MOVS
		case 0xA6: case 0xA7: // CMPS
		case 0xAA: case 0xAB: // STOS
		case 0xAC: case 0xAD: // LODS	
		case 0xAE: case 0xAF: // SCANS
			if(d_ctx->pfx_rep || d_ctx->pfx_repne) {
				// 委托给 REP 处理器
				// 注意：Exec_REP_StringOp 内部会返回 true (保持 EIP) 或 false (推进 EIP)
				// 这与 jumped 的语义完全一致
				return Exec_REP_StringOp(ctx, d_ctx);
			}
			else
			{
				// 没有前缀，执行一次，EIP 正常前进
				Exec_StringOp(ctx, d_ctx);
				return false;
			}
			break;

			// --- Sprint 5.1: Group 2 (Shift/Rotate) ---
		case 0xC0: case 0xC1: // Grp2 Eb/Ev, Ib
		case 0xD0: case 0xD1: // Grp2 Eb/Ev, 1
		case 0xD2: case 0xD3: // Grp2 Eb/Ev, CL
			Exec_Group2(ctx, d_ctx); break;
			// --- Sprint 5.2: Group 3 (MUL/DIV/NOT/NEG) ---
		case 0xF5:
			ctx->EFLAGS.CF ^= 1; break;// CMC
		case 0xF6: // Group 3 (Byte)
		case 0xF7: // Group 3 (Word/Dword)
			Exec_Group3(ctx, d_ctx);
			break;
		case 0xF8:
			ctx->EFLAGS.CF = 0; break;
		case 0xF9:
			ctx->EFLAGS.CF = 0; break;
		case 0xFA:
			ctx->EFLAGS.IF = 0; break;
		case 0xFB:
			ctx->EFLAGS.IF = 1; break;
		case 0xFC:
			ctx->EFLAGS.DF = 0; break;
		case 0xFD:
			ctx->EFLAGS.DF = 1; break;


		default:
			printf("Unimplemented: 0x%02X\n", d_ctx->opcode);
			break;
	}
	return jumped;
}

uint32_t ReadGPR(CPU_Context* ctx, int reg_index, int size) {
	if(reg_index<0 || reg_index>=8) return 0;

	if (size == 32) {
		return ctx->GPR[reg_index].I32;
	}else if(size == 16) {
		return ctx->GPR[reg_index].I16;
	}else if(size == 8) {
		if( reg_index < 4) {
			return ctx->GPR[reg_index].I8.L;
		}else {
			return ctx->GPR[reg_index - 4].I8.H;
		}
	}
	return 0;
}

bool WriteGPR(CPU_Context* ctx, int reg_index, int size, uint32_t value) {
	if (reg_index < 0 || reg_index >= 8) return 0;

	if (size == 32) {
		ctx->GPR[reg_index].I32 = value;
	}
	else if (size == 16) {
		ctx->GPR[reg_index].I16 = (WORD)value;
	}
	else if (size == 8) {
		if (reg_index < 4) {
			ctx->GPR[reg_index].I8.L = (BYTE)value;
		}
		else {
			ctx->GPR[reg_index - 4].I8.H = (BYTE)value;
		}
	}
	return 1;
}

uint32_t GetEffectiveAddress(CPU_Context* ctx, DecodeContext* d_ctx) {
	uint32_t base = 0;
	uint32_t index = 0;
	// 1. 处理 SIB 逻辑
	if (d_ctx->has_sib) {
		if (d_ctx->base != 5 && d_ctx->mod != 00) {
			base = ReadGPR(ctx, d_ctx->base, 32);
		}
		if (d_ctx->index != 4) {
			index = ReadGPR(ctx, d_ctx->index, 32);
		}
		//否则保持默认为0
	}// 2. 无 SIB 逻辑
	else {
		if (d_ctx->mod == 0 && d_ctx->modrm == 5) {
			base = 0; // disp32 直接作为地址
		}
		else {
			base = ReadGPR(ctx, d_ctx->rm, 32);
		}
	}
	return base + index * (1 << d_ctx->scale) + d_ctx->disp;
}

//参照FormatOperand对应修改
uint32_t GetOperandValue(CPU_Context* ctx, DecodeContext* d_ctx, int op_idx) {
	OperandType type;
	// 根据索引获取类型
	if(op_idx == 0) type = d_ctx->entry.op1;
	else if (op_idx == 1) type = d_ctx->entry.op2;
	else type = d_ctx->entry.op3;

	int op_size = (d_ctx->pfx_op_size == 0x66) ? 16 : 32;
	switch (type) {
		// --- 寄存器 ---
		case Gb: return ReadGPR(ctx, d_ctx->reg, 8);
		case Gw: return ReadGPR(ctx, d_ctx->reg, 16);
		case Gv: return ReadGPR(ctx, d_ctx->reg, op_size);
		// 补充对 OP_AL ... OP_rDI 的支持
		case OP_AL: return ReadGPR(ctx, 0, 8);
		case OP_CL: return ReadGPR(ctx, 1, 8);
		case OP_DL: return ReadGPR(ctx, 2, 8);
		case OP_BL: return ReadGPR(ctx, 3, 8);
		case OP_AH: return ReadGPR(ctx, 4, 8);
		case OP_CH: return ReadGPR(ctx, 5, 8);
		case OP_DH: return ReadGPR(ctx, 6, 8);
		case OP_BH: return ReadGPR(ctx, 7, 8);
		case OP_DX: return ReadGPR(ctx, 2, 16);
		case OP_rAX: return ReadGPR(ctx, 0, op_size);
		case OP_rCX: return ReadGPR(ctx, 1, op_size);
		case OP_rDX: return ReadGPR(ctx, 2, op_size);
		case OP_rBX: return ReadGPR(ctx, 3, op_size);
		case OP_rSP: return ReadGPR(ctx, 4, op_size);
		case OP_rBP: return ReadGPR(ctx, 5, op_size);
		case OP_rSI: return ReadGPR(ctx, 6, op_size);
		case OP_rDI: return ReadGPR(ctx, 7, op_size);

		// --- 内存/寄存器 (ModR/M) ---
		case Eb:
		case Ew:
		case Ev: {
			if(d_ctx->mod == 3) {
				// 寄存器直接访问
				int size_E = (type == Eb) ? 8 : ((type == Ew) ? 16 : op_size);
				return ReadGPR(ctx, d_ctx->rm, size_E);
			}
			else {
				uint32_t addr = GetEffectiveAddress(ctx, d_ctx);
				int byte_len = (type == Eb) ? 1 : ((type == Ew) ? 2 : (op_size / 8));
				return MemRead(addr, byte_len); //读取内存并返回
			}
		}
		// --- 立即数 ---
		
			// 立即数已经解析在 imm / imm2 字段中
			// 假设 op1/op2 使用 imm，op3 使用 imm2 (极少见)
			// 简单起见，这里假设只用 imm。如果指令有两个立即数(如 ENTER)，需判断
		case Ib: case Iw: case Iv: case Iz:
			return (uint32_t)d_ctx->imm;

		default:
			return 0; // 暂不支持或其他类型
	}
}

//参照FormatOperand对应修改
// 写入操作数的值
void SetOperandValue(CPU_Context* ctx, DecodeContext* d_ctx, int op_idx, uint32_t value) {
	OperandType type = (op_idx == 0) ? d_ctx->entry.op1 : d_ctx->entry.op2;
	int op_size = (d_ctx->pfx_op_size == 0x66) ? 16 : 32;
	switch (type) {
		// --- 寄存器 ---
		case Gb: WriteGPR(ctx, d_ctx->reg, 8, value); break;
		case Gw: WriteGPR(ctx, d_ctx->reg, 16, value); break;
		case Gv: WriteGPR(ctx, d_ctx->reg, op_size, value); break;
		// --- 内存/寄存器 ---
		case Eb:
		case Ew:
		case Ev: {
			if (d_ctx->mod == 3) {
				int size_E = (type == Eb) ? 8 : ((type == Ew) ? 16 : op_size);
				WriteGPR(ctx, d_ctx->rm, size_E, value);
			}
			else {
				uint32_t addr = GetEffectiveAddress(ctx, d_ctx);
				int byte_len = (type == Eb) ? 1 : ((type == Ew) ? 2 : (op_size / 8));
				MemWrite(addr, value, byte_len); // 调用提取出来的函数
			}
			break;
		}
		// 补充对 OP_AL ... OP_rDI 的支持
		case OP_AL: WriteGPR(ctx, 0, 8, value); break;
		case OP_CL: WriteGPR(ctx, 1, 8, value); break;
		case OP_DL: WriteGPR(ctx, 2, 8, value); break;
		case OP_BL: WriteGPR(ctx, 3, 8, value); break;
		case OP_AH: WriteGPR(ctx, 4, 8, value); break;
		case OP_CH: WriteGPR(ctx, 5, 8, value); break;
		case OP_DH: WriteGPR(ctx, 6, 8, value); break;
		case OP_BH: WriteGPR(ctx, 7, 8, value); break;
		case OP_DX: WriteGPR(ctx, 2, 16, value); break;
		case OP_rAX: WriteGPR(ctx, 0, op_size, value); break;
		case OP_rCX: WriteGPR(ctx, 1, op_size, value); break;
		case OP_rDX: WriteGPR(ctx, 2, op_size, value); break;
		case OP_rBX: WriteGPR(ctx, 3, op_size, value); break;
		case OP_rSP: WriteGPR(ctx, 4, op_size, value); break;
		case OP_rBP: WriteGPR(ctx, 5, op_size, value); break;
		case OP_rSI: WriteGPR(ctx, 6, op_size, value); break;
		case OP_rDI: WriteGPR(ctx, 7, op_size, value); break;
	}
}

// 处理 MOV r, i (0xB0 - 0xBF)
void Exec_MOV_Reg_Imm(CPU_Context* ctx, DecodeContext* d_ctx) {
	// 1. 读取源操作数 (OP2: Immediate)
	uint32_t src = GetOperandValue(ctx, d_ctx, 1);
	// 2. 写入目的操作数 (OP1: Register)
	// 注意：0xB8这类指令，寄存器直接编码在 Opcode 低3位，disasm 引擎会把它处理成 OP_rAX 等类型
	// 或者通用的 Opcode Table 可能会将其定义为 Gv, Iv。
	// 检查你的 opcode_table[0xB8] 定义： {"MOV",0, 0, OP_rAX, Iv, NONE, NULL}
	// 这里的 OP_rAX 是硬编码类型，不是 Gv (ModRM)。我们需要在 SetOperandValue 里支持 OP_rAX...OP_rDI

	// 为了简化 Sprint 2，我们假设你只测试 MOV EAX, 0x12345678
	// 并在 SetOperandValue 里补充对 OP_rAX 的支持：

	// [补充代码到 SetOperandValue]
	/*
	case OP_rAX: WriteGPR(ctx, 0, op_size, value); break;
	case OP_rCX: WriteGPR(ctx, 1, op_size, value); break;
	// ... 其他 OP_rXX ...
	*/

	// 如果嫌麻烦，我们先用 0xC7 (MOV r/m32, imm32) 来测试，因为它使用标准的 Ev, Iz
	// 但 0xB8 最简单。我们还是用 SetOperandValue 通用接口写回：
	SetOperandValue(ctx, d_ctx, 0, src);
}

int CalcPF(uint8_t res) {
	int count = 0;
	for (int i = 0; i < 8; i++) {
		if(res & (1 << i)) count++;
	}
	return (count % 2 == 0) ? 1 : 0;
}

void UpdateEFLAGS(CPU_Context* ctx, uint32_t res, uint32_t dest, uint32_t src, int size, ALU_Op op) {
	// 1. 提取最高位 (Sign Bit) 掩码
	uint32_t sign_mask = (size == 8) ? 0x80 : (size == 16) ? 0x8000 : 0x80000000;
	// 截断结果以符合操作数大小
	uint32_t truncated_res = res;
	if (size == 8) truncated_res &= 0xFF;
	else if (size == 16) truncated_res &= 0xFFFF;
	// 2. 通用标志位更新
	// ZF (Zero Flag): 结果为0
	ctx->EFLAGS.ZF = (truncated_res == 0) ? 1 : 0;
	// SF (Sign Flag): 结果符号位,最高位为1
	ctx->EFLAGS.SF = (truncated_res & sign_mask) ? 1 : 0;
	// PF (Parity Flag): 低8位偶校验
	ctx->EFLAGS.PF = CalcPF((uint8_t)truncated_res);
	// --- 算术特定标志位 (CF, OF, AF) ---
	// 逻辑运算 (AND/OR/XOR) 清除 CF/OF
	if (op == ALU_AND || op == ALU_OR || op == ALU_XOR) {
		ctx->EFLAGS.CF =0;
		ctx->EFLAGS.OF = 0;
		ctx->EFLAGS.AF = 0; // 未定义，通常清零
	}
	else if(op == ALU_ADD){
		// ADD: res = dest + src
		// CF (Carry): 无符号溢出 (结果小于任一操作数)
		// 注意：需比较截断前的 res 或者判断截断后的回绕
		if (size == 32) ctx->EFLAGS.CF = (res < dest);
		else ctx->EFLAGS.CF = ((res & (sign_mask << 1)) != 0); // 检查更高一位进位//bug:修复了!= 与 &优先级的问题
		// OF (Overflow): 有符号溢出 (正+正=负 或 负+负=正)
		// 公式：(dest ^ res) & (src ^ res) & sign_mask
		ctx->EFLAGS.OF = ((dest ^ truncated_res) & (src ^ truncated_res) & sign_mask)!= 0;
		// AF (Adjust): Bit 3 借位
		//加数，被加数，结果异或等于该位进位制的数学原理
		ctx->EFLAGS.AF = (dest ^ src ^ truncated_res) & 0x10 != 0;	
	}
	else if (op == ALU_SUB) {

		// SUB: res = dest - src (CMP 也是这类)
		// CF (Borrow): 无符号借位 (dest < src)
		ctx->EFLAGS.CF = (dest < src);
		// OF (Overflow): 正-负=负 或 负-正=正
		// 公式：(dest ^ src) & (dest ^ res) & sign_mask
		ctx->EFLAGS.OF = ((dest ^ src) & (dest ^ res) & sign_mask) != 0;
		// AF (Adjust): Bit 3 借位
		ctx->EFLAGS.AF = ((dest ^ res ^ truncated_res) & 0x10) != 0;
		
	}

}

// 辅助函数：获取操作数的实际位宽 (8, 16, 32)
// 用于确保 ALU 标志位计算正确
int GetOperandBitSize(CPU_Context* ctx, DecodeContext* d_ctx, OperandType type) {
	// 1. 获取前缀决定的默认大小 (16 or 32)
	int def_op_size = (d_ctx->pfx_op_size == 0x66) ? 16 : 32;

	switch (type) {
		// --- 8 位操作数 ---
		case Eb: case Gb:
		case OP_AL: case OP_CL: case OP_DL: case OP_BL:
		case OP_AH: case OP_CH: case OP_DH: case OP_BH:
			return 8;

			// --- 16 位操作数 ---
		case Ew: case Gw:
		case OP_DX: // 用于 IN/OUT
		return 16;

			// --- 依赖前缀的操作数 (16/32) ---
		case Ev: case Gv: case Gz:
		case OP_rAX: case OP_rCX: case OP_rDX: case OP_rBX:
		case OP_rSP: case OP_rBP: case OP_rSI: case OP_rDI:
			return def_op_size;

			// --- 立即数通常跟随目的操作数大小，这里作为 fallback ---
		case Ib: return 8;
		case Iw: return 16;
		case Iv: case Iz: return def_op_size;

		default:
			return def_op_size; // 默认
	}
}

void Exec_ALU_Generic(CPU_Context* ctx, DecodeContext* d_ctx, ALU_Op op, bool is_compare) {
	// 1. 确定运算位宽 (非常关键！)
	// 我们根据 Op1 (目的操作数) 的类型来决定运算是 8位 还是 32位
	// 之前漏掉了 OP_AL 等类型，现在用 GetOperandBitSize 修复
	int size_d = GetOperandBitSize(ctx, d_ctx, d_ctx->entry.op1);
	int size_s = GetOperandBitSize(ctx, d_ctx, d_ctx->entry.op2);
	// 2. 获取操作数
	uint32_t dest = GetOperandValue(ctx, d_ctx, 0); // Op1 (Dest)
	uint32_t src = GetOperandValue(ctx, d_ctx, 1); // Op2 (Src)
	// 对于 8 位和 16 位运算，必须对读取到的值进行截断清理，
	// 防止高位垃圾数据干扰标志位计算 (特别是立即数符号扩展后的高位)

	uint32_t mask_d = (size_d == 8) ? 0xFF : (size_d == 16 ? 0xFFFF : 0xFFFFFFFF);
	uint32_t mask_s = (size_s == 8) ? 0xFF : (size_s == 16 ? 0xFFFF : 0xFFFFFFFF);
	dest &= mask_d;
	src &= mask_s;
	uint32_t res = 0;

	uint32_t cf_in = ctx->EFLAGS.CF; // 获取当前的进位
	// 3. 执行计算
	switch (op) {
		case ALU_ADD: res = dest + src; break;
		case ALU_OR : res = dest | src; break;
		case ALU_ADC: res = dest + src + cf_in; break;
		case ALU_SBB: res = dest - src - cf_in; break;
		case ALU_AND: res = dest & src; break;
		case ALU_CMP: case ALU_SUB:res = dest - src; break;
		case ALU_XOR: res = dest ^ src; break;
	}
	// 3.1.在更新标志位前，先拿到截断后的结果
	uint32_t truncated_res = res & mask_d;
	// 4. 更新标志位 (传入正确的 size)
	UpdateEFLAGS(ctx, truncated_res, dest, src, size_d, op);
	// 5. 写回结果 (如果是 CMP/TEST 则跳过)
	if (!is_compare) {
		SetOperandValue(ctx, d_ctx, 0, truncated_res);
	}
}

// 处理 Group 1 指令 (0x80-0x83: ADD/OR/ADC/SBB/AND/SUB/XOR/CMP immediate)
void Exec_Group1(CPU_Context* ctx, DecodeContext* d_ctx) {
	// Group 1 的指令由 modrm.reg 字段决定操作类型
	switch (d_ctx->reg) {
		case 0: Exec_ALU_Generic(ctx, d_ctx, ALU_ADD, false); break;
		case 1: Exec_ALU_Generic(ctx, d_ctx, ALU_OR, false); break;
		case 2: Exec_ALU_Generic(ctx, d_ctx, ALU_ADC, false); break;
		case 3: Exec_ALU_Generic(ctx, d_ctx, ALU_SBB, false); break;
		case 4: Exec_ALU_Generic(ctx, d_ctx, ALU_ADD, false); break;
		case 5: Exec_ALU_Generic(ctx, d_ctx, ALU_SUB, false); break;
		case 6: Exec_ALU_Generic(ctx, d_ctx, ALU_XOR, false); break;
		case 7: Exec_ALU_Generic(ctx, d_ctx, ALU_CMP, true); break;
	}
}

// PUSH r32 / imm32 / imm8
void Exec_PUSH(CPU_Context* ctx, DecodeContext* d_ctx) {
	// 1. 读取要压入的值 (Op1)
	// 注意处理 PUSH ESP 的特殊情况：Intel 规定压入的是执行指令前的 ESP 值
	// 我们的 GetOperandValue 会读取当前的 ESP，这没问题。
	uint32_t value = GetOperandValue(ctx, d_ctx, 0);
	// 获取操作数大小 (通常是 32位，即 4字节)
	int size = (d_ctx->pfx_op_size == 0x66) ? 2 : 4;
	// 2. 调整 ESP (向下增长)
	ctx->ESP.I32 -= size;
	// 3. 写入内存
	// Host-Passthrough: 直接写入 ctx->ESP 指向的地址
	if (size == 4) {
		*(uint32_t*)ctx->ESP.I32 = value;
	}
	else {
		*(uint16_t*)ctx->ESP.I32 = (uint16_t)value;
	}
}
// POP r32
void Exec_POP(CPU_Context* ctx, DecodeContext* d_ctx) {
	int size = (d_ctx->pfx_op_size == 0x66) ? 2 : 4;
	// 1. 从栈顶读取数据
	uint32_t val = 0;
	if (size == 4) {
		val = *(uint32_t*)ctx->ESP.I32;
	}
	else {
		val = *(uint16_t*)ctx->ESP.I32;
	}
	// 2. 调整 ESP (向上收缩)
	// 注意 POP ESP 的特殊情况：它会先读栈顶数据，然后 ESP+4，最后把读出的数据覆盖回 ESP。
	// 结果就是 ESP 等于栈顶原来的那个值（ESP+4 被覆盖了）。
	ctx->ESP.I32 += size;
	// 3. 写入目的操作数 (Op1)
	SetOperandValue(ctx, d_ctx, 0, val);
}

// 检查条件跳转是否成立 (Jcc)
// condition_code: 输入指令码，取指令 Opcode 的低 4 位 (0x70-0x7F 或 0x80-0x8F 的低位)
bool CheckCondition(CPU_Context* ctx, uint8_t condition_code) {
	switch (condition_code & 0xF) {
		case 0x0: return ctx->EFLAGS.OF == 1;          // JO
		case 0x1: return ctx->EFLAGS.OF == 0;          // JNO
		case 0x2: return ctx->EFLAGS.CF == 1;          // JB, JNAE (无符号 <)
		case 0x3: return ctx->EFLAGS.CF == 0;          // JNB, JAE (无符号 >=)
		case 0x4: return ctx->EFLAGS.ZF == 1;          // JZ, JE (等于)
		case 0x5: return ctx->EFLAGS.ZF == 0;          // JNZ, JNE (不等于)
		case 0x6: return (ctx->EFLAGS.CF | ctx->EFLAGS.ZF) == 1; // JBE, JNA (无符号 <=)
		case 0x7: return (ctx->EFLAGS.CF | ctx->EFLAGS.ZF) == 0; // JA, JNBE (无符号 >)
		case 0x8: return ctx->EFLAGS.SF == 1;          // JS
		case 0x9: return ctx->EFLAGS.SF == 0;          // JNS
		case 0xA: return ctx->EFLAGS.PF == 1;          // JP, JPE
		case 0xB: return ctx->EFLAGS.PF == 0;          // JNP, JPO
		case 0xC: return ctx->EFLAGS.SF != ctx->EFLAGS.OF;       // JL, JNGE (有符号 <)
		case 0xD: return ctx->EFLAGS.SF == ctx->EFLAGS.OF;       // JNL, JGE (有符号 >=)
		case 0xE: return ctx->EFLAGS.ZF == 1 || (ctx->EFLAGS.SF != ctx->EFLAGS.OF); // JLE, JNG (有符号 <=)
		case 0xF: return ctx->EFLAGS.ZF == 0 && (ctx->EFLAGS.SF == ctx->EFLAGS.OF); // JG, JNLE (有符号 >)
	}
	return false; // 默认不跳转
}
// 处理相对跳转 (JMP, Jcc)
// 返回 true 表示跳转发生
bool Exec_Branch(CPU_Context* ctx, DecodeContext* d_ctx, bool is_conditional) {
	bool take_jump = true;
	if (is_conditional) {
		// 如果是条件跳转，先检查条件
		take_jump = CheckCondition(ctx, d_ctx->opcode);
	}
	if (take_jump) {
		// 计算目标地址
		// x86 相对跳转公式：Target = Current_EIP + Instruction_Length + Relative_Offset
		// d_ctx->imm 存储的是相对偏移 (Relative Offset)
		uint32_t offset = (uint32_t)d_ctx->imm;
		ctx->EIP += d_ctx->instr_len + offset; 
		return true; 
	}
	return false; // 未跳转
}

// 处理 CALL (相对调用)
bool Exec_CALL(CPU_Context* ctx, DecodeContext* d_ctx) {
	// 1. 计算返回地址 (下一条指令)
	uint32_t ret_addr = ctx->EIP + d_ctx->instr_len;
	// 2. 压入返回地址 (相当于 PUSH ret_addr)
	ctx->ESP.I32 -= 4;
	*(uint32_t*)ctx->ESP.I32 = ret_addr;
	
	// 3. 执行跳转
	uint32_t offset = (uint32_t)d_ctx->imm;
	ctx->EIP += d_ctx->instr_len + offset;
	return true;
}

// 处理 RET (返回)
bool Exec_RET(CPU_Context* ctx, DecodeContext* d_ctx) {
	// 1. 弹出返回地址 (相当于 POP EIP)
	uint32_t ret_addr = *(uint32_t*)ctx->ESP.I32;
	ctx->ESP.I32 += 4;
	// 2. 处理 RET n (带立即数的返回，用于平栈)
	if(d_ctx->opcode == 0xC2 || d_ctx->opcode == 0xCA) { //以后CA处理段寄存器时再实现
		ctx->ESP.I32 += d_ctx->imm;
	}
	// 3. 设置 EIP
	ctx->EIP = ret_addr;
	return true;
}

void Exec_DEC(CPU_Context* ctx, DecodeContext* d_ctx) {
	int reg = d_ctx->opcode - 0x48;
	uint32_t val = ReadGPR(ctx, reg, 32);
	uint32_t res = val - 1;
	UpdateEFLAGS(ctx, res, val, 1, 32, ALU_SUB);
	WriteGPR(ctx, reg, 32, res);
}

void Exec_INC(CPU_Context* ctx, DecodeContext* d_ctx){
	int reg = d_ctx->opcode - 0x40;
uint32_t val = ReadGPR(ctx,reg,32);
	uint32_t res = val + 1;
	UpdateEFLAGS(ctx, res, val, 1, 32, ALU_ADD);
	WriteGPR(ctx, reg, 32, res);
}

// 辅助：仅更新逻辑标志位 (ZF, SF, PF)
void UpdateLogicFlags(CPU_Context* ctx, uint32_t res, int size) {
	uint32_t truncated_res = res;
	uint32_t sign_mask = 0;

	if (size == 8) {truncated_res &= 0xFF; sign_mask = 0x80;}
	else if (size == 16) {truncated_res &= 0xFFFF; sign_mask = 0x8000;}
	else {sign_mask = 0x80000000;}
	// ZF
	ctx->EFLAGS.ZF = (truncated_res == 0) ? 1 : 0;
	ctx->EFLAGS.SF = (truncated_res & sign_mask) ? 1 : 0;
	ctx->EFLAGS.PF = CalcPF(truncated_res);
}
//处理Group2指令：SHL, SHR, SAR(移位) 和 ROL, ROR, RCL, RCR(循环移位)。
void Exec_Group2(CPU_Context* ctx, DecodeContext* d_ctx) {
	// 1. 确定位宽
	int size = GetOperandBitSize(ctx, d_ctx, d_ctx->entry.op1);
	uint32_t val = GetOperandValue(ctx, d_ctx, 0);// Dest

	// 掩码用于截断高位垃圾
	uint32_t mask = (size == 32) ? 0xFFFFFFFF : ((1 << size) - 1);
	val &= mask;
	// MSB 掩码 (最高位)
	uint32_t msb_mask = 1 << (size - 1);
	// 2. 确定移位次数 (Count)
	// D0/D1/C0/C1 等 Opcode 已经在 disasm 阶段把立即数解析到了 imm，或者 CL 解析到了 op2
	// 但 Group 2 比较特殊，我们需要手动判断一下来源
	uint32_t count = 0;
	if (d_ctx->opcode == 0xC0 || d_ctx->opcode == 0xC1){count = (uint32_t)d_ctx->imm;}
	else if (d_ctx->opcode == 0xD0 || d_ctx->opcode == 0xD1) {count = 1;}// D0/D1 固定为 1
	else if (d_ctx->opcode == 0xD2 || d_ctx->opcode == 0xD3) {count = ReadGPR(ctx, 1, 8); }// CL
	// Intel 手册规定：移位次数只取低 5 位 (0-31)
	count &= 0x1F;
	if (count == 0) return; // 0 次移位不影响标志位
	// 3. 根据 ModRM.reg 区分指令并执行
	// 使用循环模拟，每次移 1 位，确保 CF/OF 正确
	uint32_t res = val;
	uint32_t original_msb = val & msb_mask; // 用于 SAR,原符符号位
	// reg 字段定义:
	// 0=ROL, 1=ROR, 2=RCL, 3=RCR, 4=SHL/SAL, 5=SHR, 7=SAR
	switch (d_ctx->reg) {
		case 0: { // ROL (循环左移)
			for (int i = 0; i < count; i++) {
				uint32_t bit = (res & msb_mask) ? 1 : 0;
				ctx->EFLAGS.CF = bit; // CF = 移出的位
				res <<= 1;
				res |= bit; // 移出的位补到最低位
			}
			// OF (count=1): MSB ^ CF
			if (count == 1) {
				ctx->EFLAGS.OF = ((res & msb_mask) ? 1 : 0) ^ ctx->EFLAGS.CF;
			}
			break;
		}

		case 1: { // ROR (循环右移)
			for (int i = 0; i < count; i++) {
				uint32_t bit = res & 1;
				res >>= 1;
				ctx->EFLAGS.CF = bit; // CF = 移出的位
				if (bit) res |= msb_mask; // 移出的位补到最高位
			}
			if (count == 1) {
				// 根据 Intel 手册：OF = MSB(result) ^ MSB-1(result)
				uint32_t msb = (res >> (size - 1)) & 1;
				uint32_t msb_minus_1 = (res >> (size - 2)) & 1;
				ctx->EFLAGS.OF = msb ^ msb_minus_1;
			}
			break;
		}
		
		case 2: { // RCL (带进位的循环左移)
			for (int i = 0; i < count; i++) {
				uint32_t bit = (res & msb_mask) ? 1 : 0;
				res <<= 1;
				// 将 CF 补到最低位
				if (ctx->EFLAGS.CF) {
					res |= 1;
				}
				ctx->EFLAGS.CF = bit; // CF = 移出的位
			}
			// OF (count=1): MSB ^ CF
			if (count == 1) {
				ctx->EFLAGS.OF = ((res & msb_mask) ? 1 : 0) ^ ctx->EFLAGS.CF;
			}
			break;
		}

		case 3: { // RCR (带进位的循环右移)
			for (int i = 0; i < count; i++) {
				uint32_t bit = res & 1;
				res >>= 1;
				// 将 CF 补到最高位
				if (ctx->EFLAGS.CF) {
					res |= msb_mask;
				}
				ctx->EFLAGS.CF = bit; // CF = 移出的位
			}
			// OF (count=1): MSB ^ MSB-1
			if (count == 1) {
				uint32_t msb = (res >> (size - 1)) & 1;
				uint32_t msb_minus_1 = (res >> (size - 2)) & 1;
				ctx->EFLAGS.OF = msb ^ msb_minus_1;
			}
			break;
		}
		

		case 4:{// SHL / SAL (逻辑左移)
			for (int i = 0; i < count; i++) {// CF = 移出的最高位
				ctx->EFLAGS.CF = (res & msb_mask) ? 1 : 0;
				res <<= 1;
			}
			// OF (仅 count=1 时定义): 最高位是否改变 (MSB ^ CF)
			if (count == 1) {
				ctx->EFLAGS.OF = ctx->EFLAGS.CF ^ ((res & msb_mask) ? 1 : 0);
			}
			break;
		}
		
		case 5: {
			for (int i = 0; i < count; i++) {// CF = 移出的最低位
				ctx->EFLAGS.CF = res & 1;
				res >>= 1;
			}
			// OF (仅 count=1 时定义): 原最高位 (SHR 总是把最高位清0，所以看原最高位是否为1)
			if (count == 1) {
				ctx->EFLAGS.OF = (original_msb) ? 1 : 0;
			}
			break;
		}

		case 7: { // SAR (算术右移)
			for (int i = 0; i < count; i++) {
				ctx->EFLAGS.CF = res & 1;
				res >>= 1;
				// 保持符号位
				if (original_msb) {
					res |= msb_mask;
				}
			}
			// OF (仅 count=1 时定义): SAR 不改变符号位，所以 OF 总是 0
			if (count == 1) {
				ctx->EFLAGS.OF = 0;
			}
			break;
		}
		default:
			printf("Unimplemented Group 2(S/R) op: %d\n", d_ctx->reg);
			return;

	}

	// 4. 写回结果
	// 截断结果以防万
	res &= mask;
	// 更新 SF, ZF, PF
	UpdateLogicFlags(ctx, res, size);
	// 写回
	SetOperandValue(ctx, d_ctx, 0, res);
}

// 辅助：获取 Group 3 的源操作数 (Multiplier / Divisor)
// 根据你的 disasm 表定义：
// F6: MUL AL, Eb -> Op1=AL, Op2=Eb. 所以源操作数是 Op2 (index 1)
// F6: NOT Eb     -> Op1=Eb.         所以源操作数是 Op1 (index 0)
// 我们需要根据 reg 字段判断源在哪里
uint32_t GetGroup3Source(CPU_Context* ctx, DecodeContext* d_ctx) {
	// reg 0(TEST), 2(NOT), 3(NEG): 单操作数或立即数，源在 Op1 或 Op2(TEST)
	// reg 4(MUL), 5(IMUL), 6(DIV), 7(IDIV): disasm 表定义了 Op1=Acc, Op2=Src. 所以源在 Op2
	if (d_ctx->reg >= 4) {
		return GetOperandValue(ctx, d_ctx, 1);
	}
	return GetOperandValue(ctx, d_ctx, 0); // NOT/NEG
}

// 写入 Group 3 结果
void SetGroup3Dest(CPU_Context* ctx, DecodeContext* d_ctx, uint32_t val) {
	SetOperandValue(ctx, d_ctx, 0, val);
}

// 处理 Group 3 指令 (F6/F7: TEST/NOT/NEG/MUL/IMUL/DIV/IDIV)
void Exec_Group3(CPU_Context* ctx, DecodeContext* d_ctx) {
	int size = GetOperandBitSize(ctx, d_ctx, d_ctx->entry.op1);
	// 注意：对于 MUL/DIV，Op1 是 AL/AX/EAX，Op2 是 r/m。
	// 我们主要关心 r/m 的大小，但在 disasm 表里 Op1 已经反映了正确的大小 (AL=8, EAX=32)

	// 获取源操作数 (乘数 或 除数)
	uint32_t src = GetGroup3Source(ctx, d_ctx);
	// 针对 8/16 位截断源操作数，防止高位垃圾

	if (size == 8) src &= 0xFF;
	else if (size == 16) src &= 0xFFFF;

	switch (d_ctx->reg) {
		case 0: {// TEST (Iz/Ib)
		// TEST 本质是 AND，但不写回
		// 注意：F6/F7 的 TEST 指令结构通常是 TEST r/m, imm
		// disasm 表里 group_tables[3/17] 的 index 0 是 TEST。
		// 调用我们之前的通用 ALU 函数即可
			Exec_ALU_Generic(ctx, d_ctx, ALU_AND, true); // TEST (AND + 不写回)
			break;
		}
		case 2: {// NOT r/m 不影响标志位
			SetGroup3Dest(ctx, d_ctx, ~src);
			break;
		}
		case 3: {// NEG r/m 模拟 0 - src
			SetGroup3Dest(ctx, d_ctx,(0-src));
			UpdateEFLAGS(ctx, (0-src), 0, src, size, ALU_SUB);
			break;
		}
		case 4: {// MUL (Unsigned Multiply) 算法：Accumulator * src
			if (size == 8) {
				// AL * r/m8 -> AX
				uint32_t al = ctx->EAX.I8.L;
				uint32_t res = al * src;
				ctx->EAX.I16 = (uint16_t)res; // 结果写入 AX
				// 更新 CF/OF: 如果高8位(AH)非0则置位
				ctx->EFLAGS.CF = ctx->EFLAGS.OF = (res & 0xFF00) ? 1 : 0;

			}
			else if (size == 16) {
				// AX * r/m16 -> DX:AX
				uint32_t ax = ctx->EAX.I16;
				uint32_t res = ax * src;
				ctx->EDX.I16 = res >> 16; // 高16位写入 DX
				ctx->EAX.I16 = res & 0xFFFF; // 低32位写入 AX
				ctx->EFLAGS.CF = ctx->EFLAGS.OF = (ctx->EDX.I16 != 0);
			}
			else { //32
				// EAX * r/m32 -> EDX:EAX
				uint64_t eax = ctx->EAX.I32;
				uint64_t res = eax * (uint64_t)src;
				ctx->EDX.I32 = (uint32_t)(res >> 32); // 高32位写入 EDX
				ctx->EAX.I32 = (uint32_t)(res & 0xFFFFFFFF); // 低32位写入 EAX
				ctx->EFLAGS.CF = ctx->EFLAGS.OF = (ctx->EDX.I32 != 0);
			}
			break;
		}
		case 5: {
			if (size == 32) {
				int64_t eax = (int32_t)ctx->EAX.I32; //当你把一个 32 位的 int32_t 赋值给 64 位的 int64_t 时，C++ 编译器会自动触发符号扩展
				int64_t val = (int32_t)src; //如果 src 的最高位是 1，val的前 32 位就会全被填充为 1。注意不要强制类型转换成（int64_t）,注意这种默认转换和强制转换的区别
				int64_t res = eax * val;
				ctx->EDX.I32 = (uint32_t)(res >> 32); // 高32位写入 EDX
				ctx->EAX.I32 = (uint32_t)(res & 0xFFFFFFFF); // 低32位写入 EAX
			// IMUL 标志位：如果结果需要扩展到高位才能表示，则 CF=OF=1
			// 简单判断：如果 result != (int32_t)result，说明溢出了 32 位范围
				bool overflow = (res != (int64_t)(int32_t)res);
				ctx->EFLAGS.CF = ctx->EFLAGS.OF = overflow;
			}
			else if (size == 16) {
				int32_t ax = (int16_t)ctx->EAX.I16;
				int32_t val = (int16_t)src;
				int32_t res = ax * val;
				ctx->EDX.I16 = (uint32_t)(res >> 16); // 高16位写入 EDX
				ctx->EAX.I16 = (uint32_t)(res & 0xFFFF); // 低16位写入 EAX
				// IMUL 标志位：如果结果需要扩展到高位才能表示，则 CF=OF=1
				// 简单判断：如果 result != (int32_t)result，说明溢出了 32 位范围
				bool overflow = (res != (int32_t)(int16_t)res);
				ctx->EFLAGS.CF = ctx->EFLAGS.OF = overflow;
			}
			else {
				int16_t al = (int8_t)ctx->EAX.I8.L;
				int16_t val = (int8_t)src;
				int16_t res = al * val;
				ctx->EAX.I16 = (uint16_t)res; // 结果写入 AX
				bool overflow = (res != (int16_t)(int8_t)res);
				ctx->EFLAGS.CF = ctx->EFLAGS.OF = overflow;
			}
			break;
		}
		case 6: {// DIV (Unsigned Divide)
			if (src == 0) {
				printf("[CPU Error] Division by Zero at EIP=0x%08X\n", ctx->EIP);
				// 真实 CPU 会触发 Int 0 异常，这里我们暂时简单处理：不执行
				return;
			}
			if (size == 32) {
				uint64_t dividend = ((uint64_t)ctx->EDX.I32 << 32) | ctx->EAX.I32;
				uint64_t quo = dividend / src;
				uint64_t rem = dividend % src;
				if (quo > 0xFFFFFFFF) {// 商溢出
					printf("[CPU Error] quotient overflow at EIP=0x%08X\n", ctx->EIP);
					return;
				}
				ctx->EAX.I32 = (uint32_t)quo;
				ctx->EDX.I32 = (uint32_t)rem;
				// DIV 标志位未定义，不做更新
			}
			else if (size == 16) {
				uint32_t dividend = ((uint32_t)ctx->EDX.I16 << 16) | ctx->EAX.I16;
				uint32_t quo = dividend / src;
				uint32_t rem = dividend % src;
				if (quo > 0xFFFF) {// 商溢出
					printf("[CPU Error] quotient overflow at EIP=0x%08X\n", ctx->EIP);
					return;
				}
				ctx->EAX.I16 = (uint16_t)quo;
				ctx->EDX.I16 = (uint16_t)rem;
			}
			else {//8位
				uint16_t dividend = ctx->EAX.I16; //被除数：AX
				uint16_t quo = dividend / src;
				uint16_t rem = dividend % src;
				if (quo > 0xFF) {// 商溢出
					printf("[CPU Error] quotient overflow at EIP=0x%08X\n", ctx->EIP);
					return;
				}//AH(余数):AL（商）
				ctx->EAX.I8.L = (uint8_t)quo;
				ctx->EAX.I8.H = (uint8_t)rem;
			}
			break;
		}
		case 7: { // IDIV (Signed Divide)
			if (src == 0) {
				printf("[CPU Error] Division by Zero at EIP=0x%08X\n", ctx->EIP);
				return;
			}

			if (size == 8) {
				// 【8位】被除数：AX (16位有符号)
				int16_t dividend = (int16_t)ctx->EAX.I16;
				int8_t  divisor = (int8_t)src;

				// 特判 INT8_MIN / -1
				if (dividend == -128 && divisor == -1) goto overflow_label;

				int16_t quo = dividend / divisor;
				int16_t rem = dividend % divisor;

				if (quo > 127 || quo < -128) goto overflow_label;

				ctx->EAX.I8.L = (int8_t)quo; // AL
				ctx->EAX.I8.H = (int8_t)rem; // AH
			}
			else if (size == 16) {
				// 【16位】被除数：DX:AX (32位有符号拼接)
				int32_t dividend = (int32_t)(((uint32_t)ctx->EDX.I16 << 16) | (uint16_t)ctx->EAX.I16);
				int16_t divisor = (int16_t)src;

				if (dividend == (int32_t)0x80000000 && divisor == -1) goto overflow_label;

				int32_t quo = dividend / divisor;
				int32_t rem = dividend % divisor;

				if (quo > 32767 || quo < -32768) goto overflow_label;

				ctx->EAX.I16 = (int16_t)quo; // AX
				ctx->EDX.I16 = (int16_t)rem; // DX
			}
			else if (size == 32) {
				// 【32位】被除数：EDX:EAX (64位有符号拼接)
				int64_t dividend = (int64_t)(((uint64_t)ctx->EDX.I32 << 32) | (uint32_t)ctx->EAX.I32);
				int32_t divisor = (int32_t)src;

				// 特判 LLONG_MIN 情况，防止 C++ 进程直接崩溃
				if (dividend == (int64_t)0x8000000000000000 && divisor == -1) goto overflow_label;

				int64_t quo = dividend / divisor;
				int64_t rem = dividend % divisor;

				if (quo > 2147483647LL || quo < -2147483648LL) goto overflow_label;

				ctx->EAX.I32 = (uint32_t)quo; // EAX
				ctx->EDX.I32 = (uint32_t)rem; // EDX
			}
			break;

		overflow_label:
			printf("[CPU Error] IDIV Quotient Overflow at EIP=0x%08X\n", ctx->EIP);
			// 这里只 return，不修改任何寄存器，模拟真 CPU 的异常挂起行为
			return;
		}
		default:
			printf("Group 3 error opcode: %d\n", d_ctx->reg);
	}
	return;
}

uint32_t MemRead(uint32_t addr, int byte_len) {
	if (byte_len == 1) return *(uint8_t*)addr;
	else if(byte_len == 2)return *(uint16_t*)addr;
	return *(uint32_t*)addr;
}

void MemWrite(uint32_t addr, uint32_t val, int byte_len) {
	if (byte_len == 1) *(uint8_t*)addr = (uint8_t)val;
	else if(byte_len == 2) *(uint16_t*)addr = (uint16_t)val;
	else *(uint32_t*)addr = val;
}


void Exec_StringOp(CPU_Context* ctx, DecodeContext* d_ctx) {
	// 1. 确定宽度
	int bit_sz = (d_ctx->opcode & 1) ? ((d_ctx->pfx_op_size == 0x66) ? 16 : 32) : 8;
	int byte_len = bit_sz / 8;

	// 2. 预计算步长 (核心优化)
	int step = (ctx->EFLAGS.DF == 0) ? byte_len : -byte_len;

	// 3. 获取当前地址
	uint32_t esi = ctx->GPR[6].I32;
	uint32_t edi = ctx->GPR[7].I32;

	switch (d_ctx->opcode & 0xFE) {
		case 0xA4: {// MOVS
			MemWrite(edi, MemRead(esi, byte_len), byte_len);
			ctx->ESI.I32 += step;
			ctx->EDI.I32 += step;
			break;
		}
		case 0xA6: { // CMPS
			uint32_t val_src = MemRead(esi, byte_len);
			uint32_t val_dest = MemRead(edi, byte_len);
			uint32_t res = val_dest - val_src;
			UpdateEFLAGS(ctx, res, val_dest, val_src, bit_sz, ALU_SUB);
			ctx->EDI.I32 += step;
			ctx->ESI.I32 += step;
			break;
		}
		case 0xAA: { // STOS
			uint32_t val = 0;
			if (bit_sz == 8) val = ctx->EAX.I8.L;
			else if (bit_sz == 16) val = ctx->EAX.I16;
			else if (bit_sz == 32) val = ctx->EAX.I32;
			MemWrite(edi, val, byte_len);
			ctx->EDI.I32 += step;
			break;
		}
		case 0xAC: {//LODS
			uint32_t val = MemRead(esi, byte_len);
			if (bit_sz == 8) ctx->EAX.I8.L = (uint8_t)val;
			else if (bit_sz == 16) ctx->EAX.I16 = (uint16_t)val;
			else if (bit_sz == 32) ctx->EAX.I32 = val;
			ctx->ESI.I32 += step;
			break;
		}
		case 0xAE: { // SCAS
			uint32_t val_dest = MemRead(edi, byte_len);
			uint32_t val_src = 0;
			if (bit_sz == 8) val_src = ctx->EAX.I8.L;
			else if (bit_sz == 16) val_src = ctx->EAX.I16;
			else if (bit_sz == 32) val_src = ctx->EAX.I32;
			uint32_t res = val_dest - val_src;
			UpdateEFLAGS(ctx, res, val_dest, val_src, bit_sz, ALU_SUB);
			ctx->EDI.I32 += step;
			break;
		}
	}
}

bool Exec_REP_StringOp(CPU_Context* ctx, DecodeContext* d_ctx) {
	// 1. 初始检查：如果 ECX 已经到 0，循环彻底结束
	if(ctx->ECX.I32 == 0) return false;
	// 2. 执行单次操作
	Exec_StringOp(ctx, d_ctx);
	//3. 递减 ECX
	ctx->ECX.I32--;
	// 4. 判断是否要“停在原地”继续下一次循环
	// 基本条件：ECX 还没减到 0
	bool should_continue = (ctx->ECX.I32 > 0);
	// 5. 处理 SCAS / CMPS 的额外终止条件 (ZF)
	// 技巧：利用位运算快速识别 A6, A7 (CMPS) 和 AE, AF (SCAS)
	bool is_compare_op = (d_ctx->opcode & 0xA6) == 0xA6;
	if (is_compare_op && should_continue) {
		if (d_ctx->pfx_rep) {
			should_continue = (ctx->EFLAGS.ZF == 1); // REPE/REPZ
		}
		else if (d_ctx->pfx_repne) {
			should_continue = (ctx->EFLAGS.ZF == 0); // REPNE/REPNZ
		}
	}
	return should_continue;
}