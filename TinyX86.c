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

// 处理 NOP 指令的具体逻辑
void Exec_NOP(CPU_Context* ctx)
{
	// NOP 真的什么都不做，甚至不影响标志位
	// 但它是验证架构跑通的最好例子
}

// 执行分发器
void ExecuteInstruction(CPU_Context* ctx, DecodeContext* d_ctx) {
	// 我们可以根据 d_ctx->opcode 直接分发
	// 或者更高级一点，根据 d_ctx->entry.mnemonic (助记符字符串) 分发，
	// 但比较字符串效率低，建议优先使用 opcode 或 entry 中定义的唯一 ID。
	// 这里 Sprint 1 先用 Opcode。
	switch (d_ctx->opcode) {
		case 0x90: // NOP
			Exec_NOP(ctx);
			break;

			// 可以在这里预留 Sprint 2 的位置，例如 MOV
			// case 0xB8: Exec_MOV_Reg_Imm(ctx, d_ctx); break;
		//Sprint 2: 实现 MOV r32, imm32 指令 (0xB8 - 0xBF)
		case 0xB0: case 0xB1: case 0xB2: case 0xB3:
		case 0xB4: case 0xB5: case 0xB6: case 0xB7:
		case 0xB8: case 0xB9: case 0xBA: case 0xBB:
		case 0xBC: case 0xBD: case 0xBE: case 0xBF:
				// MOV r32, imm32
				Exec_MOV_Reg_Imm(ctx, d_ctx);
				break;
		default:
			printf("Warning: Unimplemented Instruction Opcode: 0x%02X (%s)\n",
				d_ctx->opcode, d_ctx->entry.mnemonic);
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
				return ReadGPR(ctx, d_ctx->reg, size_E);
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
		case Ib: case Iw: case Iv: case Iz:
			// 立即数已经解析在 imm / imm2 字段中
			// 假设 op1/op2 使用 imm，op3 使用 imm2 (极少见)
			// 简单起见，这里假设只用 imm。如果指令有两个立即数(如 ENTER)，需判断
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
				WriteGPR(ctx, d_ctx->reg, size_E, value);
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