#include "TinyX86.h"
#include <stdio.h>
#include <string.h>

// 用于打印当前机器码的辅助函数
void PrintTrace(CPU_Context* ctx, int step_count) {
    // 简单读取一下当前指令的第一个字节作为参考
    uint8_t opcode = *(uint8_t*)ctx->EIP;
    printf("[Step %2d] EIP=0x%08X | Opcode=0x%02X | EAX=0x%08X | ECX=0x%08X | ESP=0x%08X\n",
        step_count, ctx->EIP, opcode, ctx->GPR[0].I32, ctx->GPR[1].I32, ctx->ESP.I32);
}

uint8_t stack_mem[1024];

int main() {
    // ---------------------------------------------------------
    // 测试场景：函数调用与栈操作
    // 伪代码逻辑：
    //    EAX = 10;
    //    func_double(); // EAX = EAX + EAX
    //    if (EAX == 20) goto Success;
    //    EAX = -1; (Failure)
    //    return;
    // Success:
    //    NOP;
    // ---------------------------------------------------------

    uint8_t code[] = {
        // --- 主程序 Main ---
        // Offset 0: MOV EAX, 10
        0xB8, 0x0A, 0x00, 0x00, 0x00,

        // Offset 5: CALL +12 (跳转到 Offset 22: 子函数)
        // 机器码 E8 rel32。计算：Target(22) - NextIP(10) = 12 (0x0C)
        0xE8, 0x0C, 0x00, 0x00, 0x00,

        // Offset 10: CMP EAX, 20 (检查返回值是否为 20)
        // 83 F8 14 (CMP EAX, byte 20)
        0x83, 0xF8, 0x14,

        // Offset 13: JZ +6 (如果你实现了 JZ，且 ZF=1，跳转到 Offset 21)
        // 74 06 (NextIP=15, 15+6=21)
        0x74, 0x06,

        // Offset 15: MOV EAX, 0xFFFFFFFF (失败标志)
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,

        // Offset 20: NOP (失败终点)
        0x90,

        // Offset 21: NOP (成功终点，JZ 的目标)
        0x90,

        // --- 子函数 Subroutine (Offset 22) ---
        // Offset 22: PUSH EAX (测试压栈，保存现场)
        0x50,

        // Offset 23: POP ECX  (测试出栈，把 EAX 的值弹给 ECX，顺便验证数据传输)
        // 此时 ECX 应该等于 10
        0x59,

        // Offset 24: ADD EAX, ECX (EAX = 10 + 10 = 20)
        // 01 C8 (ADD EAX, ECX)
        0x01, 0xC8,

        // Offset 26: RET (返回主程序 Offset 10)
        0xC3
    };

    // 1. 初始化上下文
    CPU_Context ctx;
    memset(&ctx, 0, sizeof(ctx));

    // 2. 映射代码内存 (Host-Passthrough)
    ctx.EIP = (DWORD)code;

    // 3. 初始化栈 (关键！)
    // 模拟器直接读写内存，已在全局变量区开辟一段真实内存栈
    // ESP 指向栈底（高地址），向下增长
    ctx.ESP.I32 = (DWORD)(stack_mem + 1024);
    uint32_t initial_esp = ctx.ESP.I32;

    printf("=== Start Simulation (Call/Ret/Stack Test) ===\n");
    printf("Code Base: 0x%08X | Stack Base: 0x%08X\n", (DWORD)code, initial_esp);

    // 4. 单步执行循环
    // 这里的指令大约需要 8-9 步执行完
    int max_steps = 15;
    for (int i = 1; i <= max_steps; i++) {
        PrintTrace(&ctx, i);

        // 执行一步
        int ret = runcpu(&ctx, 1);

        if (ret != 0) {
            printf("Runtime Error!\n");
            break;
        }

        // 检查是否到达成功终点 (Offset 21)
        if (ctx.EIP == (DWORD)code + 21) {
            printf("\n[SUCCESS] Reached Success Label at Offset 21!\n");
            break;
        }

        // 检查是否到达失败终点 (Offset 20)
        if (ctx.EIP == (DWORD)code + 20) {
            printf("\n[FAILURE] Reached Failure Label. EAX = %d\n", ctx.GPR[0].I32);
            break;
        }
    }

    // 5. 最终状态验证
    printf("\n=== Final State Verification ===\n");
    printf("1. EAX Check: %s (Expected: 20, Actual: %d)\n",
        (ctx.GPR[0].I32 == 20) ? "PASS" : "FAIL", ctx.GPR[0].I32);

    printf("2. ECX Check: %s (Expected: 10, Actual: %d)\n",
        (ctx.GPR[1].I32 == 10) ? "PASS" : "FAIL", ctx.GPR[1].I32);

    printf("3. Stack Balance: %s (ESP Should be Initial Value)\n",
        (ctx.ESP.I32 == initial_esp) ? "PASS" : "FAIL");

    return 0;
}