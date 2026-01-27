#include "TinyX86.h"
#include <stdio.h>
#include <string.h>

int main() {
    /* 测试代码逻辑：
       1. MOV AL, 0xF0 (1111 0000)
       2. SHL AL, 1    -> 0xE0 (1110 0000), CF=1 (最高位1移出)
       3. SHR AL, 2    -> 0x38 (0011 1000), CF=0 (低位0移出)
       4. MOV CL, 4
       5. SAR AL, CL   -> 0x03 (0000 0011) (算术右移，符号位为0)
       6. MOV AL, 0x80
       7. SAR AL, 1    -> 0xC0 (1100 0000) (算术右移，符号位为1，保持符号)
    */
    uint8_t code[] = {
        0xB0, 0xF0,             // MOV AL, 0xF0
        0xD0, 0xE0,             // SHL AL, 1 (ModRM: reg=4 SHL, rm=0 AL. wait, D0 E0? E0 is 11 100 000. reg=4(SHL). rm=0(AL) -> ModRM 0xE0? No, 11 100 000 is E0. AL is usually index 0. Let's assume your disasm handles register mapping correctly. D0 /4 -> D0 E0 (reg=4, rm=0, mod=3))
        0xC0, 0xE8, 0x02,       // SHR AL, 2 (C0 /5, imm=2. ModRM E8: 11 101 000)

        0xB1, 0x04,             // MOV CL, 4
        0xD2, 0xF8,             // SAR AL, CL (D2 /7. ModRM F8: 11 111 000)

        // 测试 SAR 符号位保持
        0xB0, 0x80,             // MOV AL, 0x80 (-128)
        0xD0, 0xF8,             // SAR AL, 1
        0x90                    // NOP
    };

    CPU_Context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.EIP = (DWORD)code;

    printf("Sprint 5 Test: Shift & Rotate\n");

    // 1. MOV AL, F0
    runcpu(&ctx, 1);

    // 2. SHL AL, 1
    runcpu(&ctx, 1);
    printf("SHL Result: 0x%02X (Exp: E0), CF=%d (Exp: 1)\n", ctx.GPR[0].I8.L, ctx.EFLAGS.CF);

    // 3. SHR AL, 2
    runcpu(&ctx, 1);
    printf("SHR Result: 0x%02X (Exp: 38)\n", ctx.GPR[0].I8.L);

    // 4. MOV CL, 4 + SAR AL, CL
    runcpu(&ctx, 2);
    printf("SAR Result (Pos): 0x%02X (Exp: 03)\n", ctx.GPR[0].I8.L);

    // 5. MOV AL, 80 + SAR AL, 1
    runcpu(&ctx, 2);
    printf("SAR Result (Neg): 0x%02X (Exp: C0), OF=%d (Exp: 0)\n", ctx.GPR[0].I8.L, ctx.EFLAGS.OF);

    return 0;
}