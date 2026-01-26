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
		ExecuteInstruction(p, &d_ctx);
		// 3. 更新 EIP 指向下一条指令
		p->EIP += instr_len;
		// 调试打印 (可选，用于观察 Sprint 1 效果)
		printf("[Trace] EIP=0x%08X | Instr: %s | Len: %d\n", p->EIP, d_ctx.asm_str, instr_len);

	}

	return 0;
}


// 执行分发器
void ExecuteInstruction(CPU_Context* ctx, DecodeContext* d_ctx) {
	switch (d_ctx->opcode) {
		case 0x90: break; // NOP

			// MOV (上一轮实现的)
		case 0x88: case 0x89: case 0x8A: case 0x8B:
		case 0xB8: case 0xB9: case 0xBA: case 0xBB:
		case 0xBC: case 0xBD: case 0xBE: case 0xBF:
		case 0xC6: case 0xC7: 
			Exec_MOV_Reg_Imm(ctx, d_ctx); break;// 建议改名为更通用的 Exec_MOV
			

			// --- Sprint 3 新增 ---
			// Group 1 (立即数运算)
		case 0x80: case 0x81: case 0x83:
			Exec_Group1(ctx, d_ctx);break;
			// 标准 ADD (Gv, Ev 等)
		case 0x00: case 0x01: case 0x02: case 0x03: case 0x04: case 0x05:
			Exec_ALU_Generic(ctx, d_ctx, ALU_ADD, false);break;
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
			Exec_ALU_Generic(ctx, d_ctx, ALU_SUB, false);break;
			// 标准 CMP
		case 0x38: case 0x39: case 0x3A: case 0x3B: case 0x3C: case 0x3D:
			Exec_ALU_Generic(ctx, d_ctx, ALU_CMP, true); break;

		default:
			printf("Unimplemented: 0x%02X\n", d_ctx->opcode);
			break;
	}
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
				// 计算有效地址
				uint32_t addr = GetEffectiveAddress(ctx, d_ctx);
				// Host-Passthrough: 直接读取内存
				if (type == Eb) return *(uint8_t*)addr;
				if (type == Ew) return *(uint16_t*)addr;
				return *(uint32_t*)addr;
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
				// 计算有效地址
				uint32_t addr = GetEffectiveAddress(ctx, d_ctx);
				// Host-Passthrough: 直接写入内存
				if (type == Eb) *(uint8_t*)addr = (uint8_t)value;
				else if (type == Ew) *(uint16_t*)addr = (uint16_t)value;
				else *(uint32_t*)addr = value;
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
		else ctx->EFLAGS.CF = (res & (sign_mask << 1) != 0); // 检查更高一位进位
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