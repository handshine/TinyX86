#include "TinyX86.h"
#include <stdio.h>
#include <string.h>

int main() {
    // 1. 准备数据
    char src_buf[16] = "Hello";
    char dst_buf[16] = { 0 };

    // 2. 机器码指令集
    uint8_t code[] = {
        0xB8, 0,0,0,0,          // [0]  MOV EAX, src_buf (5 bytes)
        0x89, 0xC6,             // [5]  MOV ESI, EAX     (2 bytes)
        0xB8, 0,0,0,0,          // [7]  MOV EAX, dst_buf (5 bytes)
        0x89, 0xC7,             // [12] MOV EDI, EAX     (2 bytes)
        0xB9, 0x05, 0x00, 0x00, 0x00, // [14] MOV ECX, 5   (5 bytes)
        0xFC,                   // [19] CLD              (1 byte)
        0xF3, 0xA4,             // [20] REP MOVSB        (2 bytes)
        0x90                    // [22] NOP              (1 byte)
    };

    // 动态回填地址偏移量 (基于上面的索引)
    *(uint32_t*)(code + 1) = (uint32_t)src_buf;
    *(uint32_t*)(code + 8) = (uint32_t)dst_buf;

    CPU_Context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.EIP = (DWORD)code;

    printf("--- Sprint 6: REP MOVSB Verification ---\n");

    // --- 第一阶段：初始化环境 ---
    // 指令包括：2个加载EAX，2个寄存器移动，1个加载ECX，1个CLD。总计 6 条。
    runcpu(&ctx, 6);

    printf("Setup Done:\n");
    printf("  ESI (Src): 0x%X | EDI (Dst): 0x%X | ECX: %d\n",
        ctx.GPR[6].I32, ctx.GPR[7].I32, ctx.GPR[1].I32);

    // --- 第二阶段：执行 REP MOVSB ---
    // 对于 ECX=5，REP MOVSB 会执行 5 次原子操作
    // 每次操作：[EDI] = [ESI], ESI++, EDI++, ECX--
    printf("\nExecuting REP MOVSB (Step by Step):\n");
    for (int i = 0; i < 5; i++) {
        runcpu(&ctx, 1);
        printf("  Step %d: ECX=%d, Last Char Copied: '%c'\n",
            i + 1, ctx.GPR[1].I32, dst_buf[i]);
    }

    // --- 第三阶段：验证结果 ---
    printf("\n--- Final Status ---\n");
    printf("Src: %s\n", src_buf);
    printf("Dst: %s\n", dst_buf);
    printf("Final EIP Offset: %d\n", (uint8_t*)ctx.EIP - code);

    // 检查点：
    // 1. 字符串内容匹配
    // 2. ECX 归零
    // 3. EIP 应该停在 NOP (0x90) 的位置，即偏移 22
    int success = (strcmp(dst_buf, "Hello") == 0) && (ctx.GPR[1].I32 == 0);

    if (success) {
        printf("\n[SUCCESS]: String copied and registers updated correctly.\n");
    }
    else {
        printf("\n[FAILURE]: Mismatch detected!\n");
    }

    return 0;
}