#include "TinyX86.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h> 
#include <math.h>


// 辅助宏：将 32 位地址拆分为 4 个字节，用于构建机器码
#define WRITE_ADDR(addr) (uint8_t)(addr & 0xFF), (uint8_t)((addr >> 8) & 0xFF), (uint8_t)((addr >> 16) & 0xFF), (uint8_t)((addr >> 24) & 0xFF)

// 辅助函数：打印 FPU 栈
void DumpFPU(CPU_Context* ctx) {
    printf("   [FPU State] TOP=%d, SW=0x%04X\n", ctx->FPU.SW.TOP, ctx->FPU.SW.Value);
    for (int i = 0; i < 8; ++i) {
        if (ctx->FPU.Regs[i] != 0.0) // 仅打印非零寄存器简化输出
            printf("     PhysReg[%d] = %f %s\n", i, ctx->FPU.Regs[i], (i == ctx->FPU.SW.TOP) ? "<-- ST(0)" : "");
    }
}

int main() {
    printf("--- TinyX86 FPU 综合增强测试 ---\n");

    // 1. 初始化环境
    uint32_t stack_size = 1024 * 64;
    uint8_t* raw_memory = (uint8_t*)malloc(stack_size);
    if (!raw_memory) return -1;
    memset(raw_memory, 0, stack_size);

    CPU_Context cpu_instance;
    CPU_Context* ctx = &cpu_instance;
    memset(ctx, 0, sizeof(CPU_Context));

    uint32_t stack_bottom = (uint32_t)(uintptr_t)(raw_memory + stack_size - 1024);
    ctx->ESP.I32 = stack_bottom;
    ctx->DS = 0x0010; // 初始化段寄存器，防止反汇编打印乱码

    // ==========================================
    // 2. 准备数据区域
    // ==========================================
    uint32_t data_base = (uint32_t)(uintptr_t)raw_memory + 0x200;

    // Test 1 数据: (A + B) * C
    double* pA = (double*)(uintptr_t)(data_base);      *pA = 10.5;
    double* pB = (double*)(uintptr_t)(data_base + 8);  *pB = 4.5;
    double* pC = (double*)(uintptr_t)(data_base + 16); *pC = 2.0;
    double* pRes1 = (double*)(uintptr_t)(data_base + 24); *pRes1 = 0.0;

    // Test 2 数据: 整数转换 (int_in * 0.5 -> int_out)
    int32_t* pIntIn = (int32_t*)(uintptr_t)(data_base + 32); *pIntIn = 100;
    double* pFactor = (double*)(uintptr_t)(data_base + 40);  *pFactor = 0.5;
    int32_t* pIntOut = (int32_t*)(uintptr_t)(data_base + 48); *pIntOut = 0;

    // Test 3 数据: 科学计算结果 (sin(pi/2))
    double* pSinRes = (double*)(uintptr_t)(data_base + 56); *pSinRes = 0.0;

    // Test 4 数据: 状态字存储
    uint16_t* pStatusWord = (uint16_t*)(uintptr_t)(data_base + 64); *pStatusWord = 0;

    // ==========================================
    // 3. 构建机器码
    // ==========================================
    uint8_t* code_ptr = raw_memory + 0x1000;
    ctx->EIP = (uint32_t)(uintptr_t)code_ptr;

    uint8_t machine_code[] = {
        // --- Test 1: 基础浮点运算 (A + B) * C ---
        // FLD qword ptr [pA]
        0xDD, 0x05, WRITE_ADDR((uint32_t)(uintptr_t)pA),
        // FADD qword ptr [pB]
        0xDC, 0x05, WRITE_ADDR((uint32_t)(uintptr_t)pB),
        // FMUL qword ptr [pC]
        0xDC, 0x0D, WRITE_ADDR((uint32_t)(uintptr_t)pC),
        // FSTP qword ptr [pRes1]
        0xDD, 0x1D, WRITE_ADDR((uint32_t)(uintptr_t)pRes1),

        // --- Test 2: 整数交互 (FILD / FISTP) ---
        // FILD dword ptr [pIntIn]  ; 加载整数 100 -> 100.0
        0xDB, 0x05, WRITE_ADDR((uint32_t)(uintptr_t)pIntIn),
        // FMUL qword ptr [pFactor] ; 100.0 * 0.5 -> 50.0
        0xDC, 0x0D, WRITE_ADDR((uint32_t)(uintptr_t)pFactor),
        // FISTP dword ptr [pIntOut]; 保存为整数 50
        0xDB, 0x1D, WRITE_ADDR((uint32_t)(uintptr_t)pIntOut),

        // --- Test 3: 科学计算 (FSIN, FABS) ---
        // FLDPI (加载 PI)
        0xD9, 0xEB,
        // FIDIV dword ptr [pC] (PI / 2, 这里 pC 是 double 2.0，不能直接用 FIDIV m32，
        // 为了方便我们直接用 FSCALE 或简单用常量。这里演示 FABS 和 FCHS)

        // 我们改测: FCHS (变负) -> FABS (变正)
        // FLD1 (加载 1.0)
        0xD9, 0xE8,
        // FCHS (变成 -1.0)
        0xD9, 0xE0,
        // FABS (变回 1.0)
        0xD9, 0xE1,
        // FSTP qword ptr [pSinRes] (存结果)
        0xDD, 0x1D, WRITE_ADDR((uint32_t)(uintptr_t)pSinRes),
        // 清理 PI (FSTP ST(0))
        0xDD, 0xD8,

        // --- Test 4: 比较指令 (FCOM) ---
        // FLD1 (1.0)
        0xD9, 0xE8,
        // FLD1 (1.0) -> Stack: 1.0, 1.0
        0xD9, 0xE8,
        // FADD ST(0), ST(0) -> Stack: 2.0, 1.0
        0xD8, 0xC0,
        // FCOM ST(1) ; 比较 2.0 和 1.0
        0xD8, 0xD1,
        // FNSTSW AX (DF E0) ; 保存状态字到 AX
        0xDF, 0xE0,
        // MOV [pStatusWord], AX (A3 ...)
        0x66, 0xA3, WRITE_ADDR((uint32_t)(uintptr_t)pStatusWord),

        // 结束
        0xC3
    };

    memcpy(code_ptr, machine_code, sizeof(machine_code));

    // 设置虚拟返回地址
    uint32_t magic_ret = 0xDEADBEEF;
    ctx->ESP.I32 -= 4;
    *(uint32_t*)ctx->ESP.I32 = magic_ret;

    // ==========================================
    // 4. 执行
    // ==========================================
    printf("开始执行...\n");
    int steps = 0;
    while (ctx->EIP != magic_ret && steps < 200) {
        if (runcpu(ctx, 1) != 0) {
            printf("CPU 执行错误!\n");
            break;
        }
        steps++;
    }
    printf("执行结束，共 %d 步。\n\n", steps);

    // ==========================================
    // 5. 结果验证
    // ==========================================

    // --- 验证 1: 浮点运算 ---
    printf("Test 1: (10.5 + 4.5) * 2.0\n");
    printf("  Expected: 30.00\n");
    printf("  Actual:   %.2f\n", *pRes1);
    if (fabs(*pRes1 - 30.0) < 0.001) printf("  [PASS]\n");
    else printf("  [FAIL]\n");

    // --- 验证 2: 整数转换 ---
    printf("\nTest 2: int(100) * 0.5 -> int\n");
    printf("  Expected: 50\n");
    printf("  Actual:   %d\n", *pIntOut);
    if (*pIntOut == 50) printf("  [PASS]\n");
    else printf("  [FAIL]\n");

    // --- 验证 3: 科学计算 (FABS测试) ---
    printf("\nTest 3: FABS(-1.0)\n");
    printf("  Expected: 1.00\n");
    printf("  Actual:   %.2f\n", *pSinRes);
    if (fabs(*pSinRes - 1.0) < 0.001) printf("  [PASS]\n");
    else printf("  [FAIL]\n");

    // --- 验证 4: 比较 (2.0 > 1.0) ---
    // 2.0 > 1.0，则 C3=0, C2=0, C0=0。
    // 如果相等(C3=1)，如果小于(C0=1)。
    // SW 的 C0 在 bit 8, C2 在 bit 10, C3 在 bit 14。
    // 0x0000 表示 > (Greater)
    printf("\nTest 4: FCOM (2.0 vs 1.0)\n");
    uint16_t sw = *pStatusWord;
    int c0 = (sw >> 8) & 1;
    int c2 = (sw >> 10) & 1;
    int c3 = (sw >> 14) & 1;
    printf("  SW: 0x%04X (C3=%d, C2=%d, C0=%d)\n", sw, c3, c2, c0);

    if (c0 == 0 && c2 == 0 && c3 == 0) {
        printf("  [PASS] 比较结果正确 (2.0 > 1.0)\n");
    } else {
        printf("  [FAIL] 比较结果错误\n");
    }

    free(raw_memory);
    return 0;
}