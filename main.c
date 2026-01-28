#include "TinyX86.h"
#include <stdio.h>
#include <string.h>

int main() {
    /* 测试逻辑：
       1. MOV EAX, 10       (B8 0A 00 00 00)
       2. MOV ECX, 5        (B9 05 00 00 00)
       3. MUL ECX           (F7 E1) -> EDX:EAX = 50 (0x32)
       4. MOV EBX, EAX      (89 C3) -> 备份 50 到 EBX
       5. NOT EAX           (F7 D0) -> 按位取反
       6. NEG EBX           (F7 DB) -> 变负数 (-50)
       7. DIV ECX           (F7 F1) -> 这里有个坑！DIV 除的是 EDX:EAX。
                                       如果不清空 EDX，会除出天文数字甚至溢出。
                                       所以我们先 XOR EDX, EDX。
    */
    uint8_t code[] = {
        0xB8, 0x0A, 0x00, 0x00, 0x00,   // MOV EAX, 10
        0xB9, 0x05, 0x00, 0x00, 0x00,   // MOV ECX, 5
        0xF7, 0xE1,                     // MUL ECX

        // 验证 NEG
        0x89, 0xC3,                     // MOV EBX, EAX (50)
        0xF7, 0xDB,                     // NEG EBX (-50 = 0xFFFFFFCE)

        // 验证 DIV (需要先清零 EDX，为了方便测试，我直接用 MOV EDX, 0)
        0xBA, 0x00, 0x00, 0x00, 0x00,   // MOV EDX, 0
        0xB8, 0x64, 0x00, 0x00, 0x00,   // MOV EAX, 100 (0x64)
        0xF7, 0xF1,                     // DIV ECX (100 / 5 = 20)

        0x90                            // NOP
    };

    CPU_Context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.EIP = (DWORD)code;

    printf("Sprint 5 Test: MUL / DIV / NEG\n");

    // 1. Init
    runcpu(&ctx, 2);

    // 2. MUL ECX
    runcpu(&ctx, 1);
    printf("MUL Res: EAX=%d (Exp: 50), EDX=%d\n", ctx.GPR[0].I32, ctx.GPR[2].I32);

    // 3. NEG EBX
    runcpu(&ctx, 2); // MOV + NEG
    printf("NEG Res: EBX=0x%X (Exp: 0xFFFFFFCE / -50)\n", ctx.GPR[3].I32);

    // 4. DIV ECX
    runcpu(&ctx, 3); // MOV EDX + MOV EAX + DIV
    printf("DIV Res: EAX=%d (Exp: 20), EDX=%d (Rem: 0)\n", ctx.GPR[0].I32, ctx.GPR[2].I32);

    return 0;
}