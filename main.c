// [main.c] 修复版
#include "TinyX86.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h> 

int main() {
    printf("--- Sprint 9: Segments & Sign Extensions (Fixed) ---\n");

    // 1. 初始化
    uint32_t stack_size = 1024 * 64;
    uint8_t* raw_memory = (uint8_t*)malloc(stack_size);
    if (!raw_memory) return -1;
    CPU_Context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ESP.I32 = (uint32_t)(uintptr_t)(raw_memory + stack_size - 1024);

    // =========================================================
    // 2. 构造机器码
    // =========================================================
    uint8_t code[] = {
        // --- Test 1: Segment Registers (MOV & PUSH/POP) ---
        // MOV AX, 0x1234
        0xB8, 0x34, 0x12, 0x00, 0x00,
        // MOV DS, AX (0x8E D8) -> DS 应该是 0x1234
        0x8E, 0xD8,
        // MOV BX, DS (0x8C DB) -> BX 应该是 0x1234
        0x8C, 0xDB,

        // PUSH DS (0x1E) -> 栈里压入 0x1234
        0x1E,
        // POP ES (0x07) -> ES 弹出 0x1234
        0x07,

        // --- Test 2: Sign Extensions (CWDE / CDQ) ---
        // MOV EAX, 0xFFFF8000 (-32768) 
        // 低16位是 0x8000 (负数)，CWDE 后 EAX 应该保持 0xFFFF8000
        0xB8, 0x00, 0x80, 0xFF, 0xFF,

        // MOV AX, 0x007F (127) -> EAX 变为 0xFFFF007F (高位保留了垃圾)
        0x66, 0xB8, 0x7F, 0x00,
        // CWDE (0x98) -> AX(0x007F) 符号扩展到 EAX。EAX 应该变为 0x0000007F
        0x98,

        // MOV EAX, -1 (0xFFFFFFFF)
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,
        // CDQ (0x99) -> EDX:EAX。因为 EAX 是负数，EDX 应该变为 0xFFFFFFFF
        // 【关键点】：这个值必须保留到最后验证！
        0x99,

        // --- Test 3: TEST Instruction ---
        // MOV ECX, 0x0F
        0xB9, 0x0F, 0x00, 0x00, 0x00,

        // TEST ECX, ECX (0x85 C9) -> 0x0F & 0x0F = 0x0F. ZF=0.
        0x85, 0xC9,

        // 【修复】：改用 ESI (索引6) 来做测试，不要覆盖 EDX！
        // MOV ESI, 0 
        0xBE, 0x00, 0x00, 0x00, 0x00,

        // TEST ECX, ESI 
        // Opcode 0x85, ModRM: Mode=11, Reg=ESI(6, 110), RM=ECX(1, 001) -> 11 110 001 -> 0xF1
        // 结果: 0x0F & 0x00 = 0. ZF 应该被置为 1.
        0x85, 0xF1,

        0x90 // NOP
    };

    ctx.EIP = (uint32_t)(uintptr_t)code;
    runcpu(&ctx, 15);

    // =========================================================
    // 3. 结果验证
    // =========================================================
    printf("\n--- Verification ---\n");

    // Segment Test
    printf("DS: 0x%04X (Expected 0x1234)\n", ctx.DS);
    printf("ES: 0x%04X (Expected 0x1234)\n", ctx.ES);

    // Sign Extension Test
    // 验证 CDQ 的结果：EDX 必须是 0xFFFFFFFF
    printf("EDX (CDQ): 0x%08X (Expected 0xFFFFFFFF)\n", ctx.GPR[2].I32);

    // TEST Test
    // 验证最后一条 TEST ECX, ESI 的结果：ZF 必须是 1
    printf("ZF (TEST): %d (Expected 1)\n", ctx.EFLAGS.ZF);

    int success = 1;
    if (ctx.DS != 0x1234) success = 0;
    if (ctx.ES != 0x1234) success = 0;
    if (ctx.GPR[2].I32 != 0xFFFFFFFF) success = 0; // 之前这里会失败
    if (ctx.EFLAGS.ZF != 1) success = 0;

    if (success) {
        printf("[SUCCESS] All Sprint 9 features work!\n");
    }
    else {
        printf("[FAIL] Check debug output.\n");
    }

    free(raw_memory);
    return 0;
}