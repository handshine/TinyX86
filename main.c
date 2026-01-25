#include "TinyX86.h"
#include <stdio.h>

int main() {
    // 机器码：MOV EAX, 0x12345678 (B8 78 56 34 12) + NOP (90)
    uint8_t code[] = { 0xB8, 0x78, 0x56, 0x34, 0x12, 0x90 ,0xB0 ,0x78,0xb1,0x56};

    CPU_Context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.EIP = (DWORD)code;

    printf("Sprint 2 Test: MOV EAX, imm32\n");
    runcpu(&ctx, 4); // 执行四条指令

    printf("EAX = 0x%08X\n", ctx.EAX.I32); // 应该输出 0x12345678
	printf("ECX = 0x%08X\n", ctx.ECX.I32); // 应该输出 0x00000056

    if (ctx.EAX.I32 == 0x12345678) {
        printf("SUCCESS: Operand Resolver working!\n");
    }
    else {
        printf("FAILURE: EAX incorrect.\n");
    }
    return 0;
}