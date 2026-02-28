# TinyX86

一个轻量级的 x86（IA-32）CPU 模拟器，用纯 C 实现，包含完整的指令解码器与执行引擎，并支持 x87 FPU 浮点运算。

---

## 目录

- [项目简介](#项目简介)
- [模块架构](#模块架构)
- [CPU 寄存器布局](#cpu-寄存器布局)
- [指令解码流水线](#指令解码流水线)
- [指令执行流程](#指令执行流程)
- [支持的指令集](#支持的指令集)
- [FPU 子系统](#fpu-子系统)
- [快速上手](#快速上手)
- [测试](#测试)
- [文件结构](#文件结构)

---

## 项目简介

TinyX86 是一个教学/研究用途的 x86-32 CPU 模拟器，核心由两大模块组成：

| 模块 | 文件 | 职责 |
|------|------|------|
| 解码器 (Disassembler) | `disasm.c` / `disasm.h` | 从字节流中解析 x86 指令，填充 `DecodeContext` |
| 执行引擎 (Executor) | `TinyX86.c` / `TinyX86.h` | 根据 `DecodeContext` 执行指令，更新 `CPU_Context` |

---

## 模块架构

```mermaid
graph TD
    subgraph 用户程序
        A[main.c / 测试代码]
    end

    subgraph 解码层
        B[disasm.h\nDecodeContext / OpcodeEntry]
        C[disasm.c\nDisassemble / ParseInstuction\nParseModRM / ParseSIB\nParseImmediate / ParseFPU]
    end

    subgraph 执行层
        D[TinyX86.h\nCPU_Context / FPU_Context\nREG32 / EFLAGS]
        E[TinyX86.c\nruncpu / ExecuteInstruction\nExec_ALU / Exec_FPU\nExec_Branch / Exec_String...]
    end

    subgraph 数据结构
        F[(CPU_Context\nGPR × 8\nEIP / EFLAGS\nSeg × 6\nFPU_Context)]
        G[(DecodeContext\nopcode / modrm\nSIB / disp / imm\nOperandType)]
    end

    A -->|写入机器码\n设置 EIP| F
    A -->|调用 runcpu| E
    E -->|调用| C
    C -->|填充| G
    E -->|读写| F
    B --> G
    D --> F
```

---

## CPU 寄存器布局

```mermaid
block-beta
  columns 4

  block:gpr["通用寄存器 (GPR)"]:2
    EAX ECX
    EDX EBX
    ESP EBP
    ESI EDI
  end

  block:ctrl["控制寄存器"]:1
    EIP
    EFLAGS
  end

  block:seg["段寄存器"]:1
    ES CS
    SS DS
    FS GS
  end

  block:fpu["x87 FPU"]:4
    SW["Status Word\n(C0/C1/C2/C3/TOP)"]
    CW["Control Word\n(PC/RC/IM...)"]
    ST0 ST1
    ST2 ST3
    ST4 ST5
    ST6 ST7
  end
```

### EFLAGS 标志位

```mermaid
packet-beta
  0-0: "CF"
  1-1: "-"
  2-2: "PF"
  3-3: "-"
  4-4: "AF"
  5-5: "-"
  6-6: "ZF"
  7-7: "SF"
  8-8: "TF"
  9-9: "IF"
  10-10: "DF"
  11-11: "OF"
  12-13: "IOPL"
  14-14: "NT"
  15-31: "reserved"
```

---

## 指令解码流水线

```mermaid
flowchart LR
    RAW["字节流\nbuffer[]"]
    --> PFX["ParsePrefixes\n识别 REP/LOCK/\n0x66/0x67/段前缀"]
    --> OPC["读取 Opcode\n查 opcode_table\n(单/双字节)"]
    --> MODRM["ParseModRM\nmod / reg / rm"]
    --> SIB["ParseSIB\nscale / index / base"]
    --> DISP["ParseDisplacement\n0 / 8 / 32 位偏移"]
    --> IMM["ParseImmediate\nIb / Iw / Iv / Iz"]
    --> CTX["DecodeContext\n完整解码结果"]
```

---

## 指令执行流程

```mermaid
flowchart TD
    Start([runcpu 调用]) --> Fetch["从 EIP 读取字节\nDisassemble / ParseInstuction"]
    Fetch --> Decode["填充 DecodeContext\n(opcode, modrm, imm, ...)"]
    Decode --> Dispatch{"ExecuteInstruction\n按 opcode 分派"}

    Dispatch -->|"0x90 NOP"| NOP[Exec_NOP]
    Dispatch -->|"0x80-0x83 Group1"| G1[Exec_Group1\nADD/OR/ADC/SBB\nAND/SUB/XOR/CMP]
    Dispatch -->|"0x88-0x8E MOV"| MOV[Exec_MOV_Generic]
    Dispatch -->|"0x50-0x5F PUSH/POP"| STACK[Exec_PUSH / Exec_POP]
    Dispatch -->|"0x70-0x7F / 0x0F80 Jcc"| BRANCH[Exec_Branch\nCheckCondition]
    Dispatch -->|"0xE8 CALL / 0xC3 RET"| CALLRET[Exec_CALL / Exec_RET]
    Dispatch -->|"0xC0-0xD3 Group2"| G2[Exec_Group2\nSHL/SHR/SAR\nROL/ROR/RCL/RCR]
    Dispatch -->|"0xF6-0xF7 Group3"| G3[Exec_Group3\nMUL/IMUL/DIV/IDIV\nNOT/NEG/TEST]
    Dispatch -->|"0xA4-0xAF 串操作"| STR[Exec_StringOp\nMOVS/STOS/LODS\nCMPS/SCAS]
    Dispatch -->|"0xD8-0xDF FPU"| FPU[Exec_FPU\nFLD/FST/FADD/FSUB\nFMUL/FDIV/FCOM...]

    NOP & MOV & STACK & G1 & G2 & G3 & STR & BRANCH & CALLRET & FPU --> UpdateEIP["jumped?\n是: EIP 已更新\n否: EIP += instr_len"]
    UpdateEIP --> End([返回 steps])
```

---

## 支持的指令集

```mermaid
mindmap
  root((TinyX86\n指令集))
    数据传送
      MOV r/m, r/imm
      MOVZX / MOVSX
      XCHG
      LEA
      PUSH / POP
      PUSHF / POPF
      PUSHAD / POPAD
      ENTER / LEAVE
    算术运算
      ADD / ADC
      SUB / SBB
      INC / DEC
      MUL / IMUL
      DIV / IDIV
      NEG / NOT
      CBW / CWDE
      CWD / CDQ
    逻辑与位移
      AND / OR / XOR
      SHL / SHR / SAR
      ROL / ROR
      RCL / RCR
      TEST / CMP
    跳转与调用
      JMP rel8/rel32/r/m
      Jcc 短/近跳转
      CMOVcc
      CALL rel / r/m
      RET / RET n
      LOOP / LOOPcc
    串操作
      MOVS / MOVSB / MOVSD
      STOS / STOSB / STOSD
      LODS / LODSB / LODSD
      CMPS / SCAS
      REP / REPE / REPNE 前缀
    标志操作
      SAHF / LAHF
      SETcc
      PUSHF / POPF
    系统
      NOP
      HLT
      INT n / INT 3
    x87 FPU
      FLD / FST / FSTP
      FADD / FSUB / FMUL / FDIV
      FCOM / FCOMP / FTST
      FABS / FCHS / FSQRT
      FSIN / FCOS / FTAN
      FILD / FIST / FISTP
      FLDPI / FLD1 / FLDZ
      FNSTSW AX
```

---

## FPU 子系统

x87 FPU 采用 8 个物理寄存器（R0–R7）加一个栈顶指针 TOP 实现寄存器栈。

```mermaid
sequenceDiagram
    participant Code as 机器码
    participant CPU  as CPU 执行引擎
    participant Stack as FPU 寄存器栈<br/>(R0–R7 + TOP)
    participant Mem  as 内存

    Code->>CPU: FLD qword ptr [pA]
    CPU->>Mem: MemReadF(addr, 64)
    Mem-->>CPU: 10.5
    CPU->>Stack: FPU_PUSH(10.5) — TOP--

    Code->>CPU: FADD qword ptr [pB]
    CPU->>Mem: MemReadF(addr, 64)
    Mem-->>CPU: 4.5
    CPU->>Stack: ST(0) += 4.5 → 15.0

    Code->>CPU: FMUL qword ptr [pC]
    CPU->>Mem: MemReadF(addr, 64)
    Mem-->>CPU: 2.0
    CPU->>Stack: ST(0) *= 2.0 → 30.0

    Code->>CPU: FSTP qword ptr [pRes]
    CPU->>Stack: FPU_POP() — TOP++
    Stack-->>CPU: 30.0
    CPU->>Mem: MemWriteF(addr, 30.0, 64)

    Note over Stack: FPU Status Word 记录<br/>C0/C1/C2/C3 比较标志<br/>TOP 当前栈顶位置
```

---

## 快速上手

### 编译（Windows / MSVC）

使用 Visual Studio 打开 `TinyX86.slnx`，直接生成即可。

### 核心 API

```c
#include "TinyX86.h"

// 1. 初始化 CPU 上下文
CPU_Context ctx;
memset(&ctx, 0, sizeof(CPU_Context));

// 2. 准备内存与机器码
uint8_t memory[64 * 1024];
memset(memory, 0, sizeof(memory));
ctx.ESP.I32 = (uint32_t)(uintptr_t)(memory + sizeof(memory) - 1024);

uint8_t* code = memory + 0x1000;
ctx.EIP = (uint32_t)(uintptr_t)code;

// 写入机器码: MOV EAX, 42  (B8 2A 00 00 00)
code[0] = 0xB8; code[1] = 42; code[2] = 0; code[3] = 0; code[4] = 0;
code[5] = 0xC3; // RET

// 3. 压入返回地址
uint32_t magic = 0xDEADBEEF;
ctx.ESP.I32 -= 4;
*(uint32_t*)ctx.ESP.I32 = magic;

// 4. 逐步执行
while (ctx.EIP != magic) {
    runcpu(&ctx, 1);
}

printf("EAX = %u\n", ctx.EAX.I32); // 输出: EAX = 42
```

### 主要接口

| 函数 | 说明 |
|------|------|
| `runcpu(ctx, step)` | 执行 `step` 条指令，返回 0 成功 |
| `ExecuteInstruction(ctx, d_ctx)` | 执行单条已解码指令 |
| `ReadGPR(ctx, index, size)` | 读通用寄存器（8/16/32 位）|
| `WriteGPR(ctx, index, size, val)` | 写通用寄存器 |
| `GetEffectiveAddress(ctx, d_ctx)` | 计算有效地址 |
| `GetOperandValue(ctx, d_ctx, idx)` | 读操作数值 |
| `SetOperandValue(ctx, d_ctx, idx, val)` | 写操作数值 |
| `MemRead(addr, bytes)` | 读内存（1/2/4 字节）|
| `MemWrite(addr, val, bytes)` | 写内存 |
| `UpdateEFLAGS(ctx, res, dst, src, size, op)` | 更新标志位 |

---

## 测试

测试位于 `Sample-Test1/` 目录，使用 **Google Test** 框架。覆盖内容包括：

- 通用寄存器读写（`ReadWriteGprHandlesSizesAndInvalid`）
- 有效地址计算（ModRM、SIB、位移）
- 操作数读写
- ALU 运算（ADD/SUB/AND/OR/XOR/CMP）
- EFLAGS 更新（CF/ZF/OF/SF/PF）
- 移位/循环移位（Group2）
- 乘除法（Group3）
- PUSH/POP 栈操作
- 分支（Jcc、JMP、CALL、RET）
- INC/DEC
- `runcpu` 集成测试

---

## 文件结构

```
TinyX86/
├── disasm.h          # 解码数据结构与接口声明
├── disasm.c          # 指令解码实现（opcode 表、ModRM、SIB、立即数解析）
├── TinyX86.h         # CPU 上下文结构、执行接口声明
├── TinyX86.c         # 指令执行实现（ALU、FPU、跳转、串操作……）
├── main.c            # FPU 综合演示程序
├── Sample-Test1/
│   ├── test.cpp      # Google Test 单元测试
│   ├── pch.h / pch.cpp
│   └── packages.config
├── TinyX86.slnx      # Visual Studio 解决方案
└── TinyX86.vcxproj   # Visual Studio 项目文件
```
