#include "TinyX86.h"
#include <stdio.h>

static void run_steps(CPU_Context* ctx, int steps, const char* title)
{
    printf("\n== %s ==\n", title);
    for (int i = 0; i < steps; i++) {
        runcpu(ctx, 1);
        printf("第%d步: EAX=0x%08X ZF=%d SF=%d CF=%d OF=%d AF=%d PF=%d\n\n",
            i + 1,
            ctx->GPR[0].I32,
            ctx->EFLAGS.ZF,
            ctx->EFLAGS.SF,
            ctx->EFLAGS.CF,
            ctx->EFLAGS.OF,
            ctx->EFLAGS.AF,
            ctx->EFLAGS.PF);
    }
}

int main() {
    // 机器码序列：
    // 1. B8 10 00 00 00    MOV EAX, 0x10
    // 2. 83 C0 20          ADD EAX, 0x20  -> EAX=0x30, ZF=0
    // 3. 83 E8 30          SUB EAX, 0x30  -> EAX=0x00, ZF=1
    // 4. 83 F8 00          CMP EAX, 0      -> ZF=1
    // 5. B8 FF FF FF 7F    MOV EAX, 0x7FFFFFFF
    // 6. 83 C0 01          ADD EAX, 1      -> EAX=0x80000000, OF=1, SF=1
    // 7. B8 00 00 00 80    MOV EAX, 0x80000000
    // 8. 83 E8 01          SUB EAX, 1      -> EAX=0x7FFFFFFF, OF=1
    // 9. B8 00 00 00 00    MOV EAX, 0
    // 10. 83 E8 01         SUB EAX, 1      -> EAX=0xFFFFFFFF, CF=1, SF=1
    // 11. 83 C0 01         ADD EAX, 1      -> EAX=0x00000000, CF=1, ZF=1
    // 12. 83 E0 0F         AND EAX, 0x0F   -> EAX=0, ZF=1
    // 13. 83 F0 FF         XOR EAX, 0xFF   -> EAX=0x000000FF, ZF=0
    uint8_t code[] = {
        0xB8, 0x10, 0x00, 0x00, 0x00,
        0x83, 0xC0, 0x20,
        0x83, 0xE8, 0x30,

        0x83, 0xF8, 0x00,

        0xB8, 0xFF, 0xFF, 0xFF, 0x7F,
        0x83, 0xC0, 0x01,

        0xB8, 0x00, 0x00, 0x00, 0x80,
        0x83, 0xE8, 0x01,

        0xB8, 0x00, 0x00, 0x00, 0x00,
        0x83, 0xE8, 0x01,
        0x83, 0xC0, 0x01,

        0x83, 0xE0, 0x0F,
        0x83, 0xF0, 0xFF
    };

    CPU_Context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.EIP = (DWORD)code;

    printf("Sprint 3 测试：ALU 与标志位（不使用反汇编输出）\n");

    run_steps(&ctx, 3, "基础：MOV/ADD/SUB -> ZF");
    if (ctx.GPR[0].I32 == 0 && ctx.EFLAGS.ZF == 1) {
        printf("成功：SUB 结果为 0，且 ZF=1。\n");
    }
    else {
        printf("失败：0/ZF 校验未通过。EAX=0x%08X ZF=%d\n", ctx.GPR[0].I32, ctx.EFLAGS.ZF);
    }

    run_steps(&ctx, 1, "CMP EAX,0（不改 EAX，只影响标志位）");
    if (ctx.EFLAGS.ZF == 1) {
        printf("成功：CMP 设置了 ZF=1。\n");
    }
    else {
        printf("失败：CMP 的 ZF 期望为 1，实际为 %d\n", ctx.EFLAGS.ZF);
    }

    run_steps(&ctx, 2, "ADD 溢出测试（0x7FFFFFFF + 1）");

    run_steps(&ctx, 2, "SUB 溢出测试（0x80000000 - 1）");

    run_steps(&ctx, 3, "借位/进位链：0 - 1；再 +1");

    run_steps(&ctx, 2, "逻辑运算：AND/XOR");

    return 0;
}