// [main.c]
#include "TinyX86.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h> 

int main() {
    printf("--- Sprint 10: Hello World (INT 21h & LOOP) ---\n");

    // 1. 初始化内存
    uint32_t stack_size = 1024 * 64;
    uint8_t* raw_memory = (uint8_t*)malloc(stack_size);
    if (!raw_memory) return -1;

    CPU_Context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ESP.I32 = (uint32_t)(uintptr_t)(raw_memory + stack_size - 1024);

    // 2. 在内存某处放入字符串 "Hello"
    // 我们把字符串放在偏移 0x1000 处
    uint32_t str_addr = 0x1000;
    const char* msg = "Hello";
    // 既然我们是 Host-Passthrough 内存模型，raw_memory 只是栈，
    // 我们需要把字符串真的写到 ctx 可以访问的地址。
    // 简单起见，我们直接把字符串跟在代码后面，或者手动写入 raw_memory
    // 但我们的 MemRead 目前是直接读绝对地址的。
    // 为了方便，我们把字符串拷贝到 raw_memory 的开头部分作为数据区
    memcpy(raw_memory, msg, 6);
    // 获取 raw_memory 在宿主机的真实地址作为“数据段地址”
    uint32_t host_str_addr = (uint32_t)(uintptr_t)raw_memory;


    // =========================================================
    // 3. 构造机器码
    // =========================================================
    // 代码放在 raw_memory + 0x100 处，防止覆盖数据
    uint8_t* code_ptr = raw_memory + 0x100;
    uint32_t code_start_addr = (uint32_t)(uintptr_t)code_ptr;

    uint8_t assembly[] = {
        // MOV ECX, 5 (循环次数)
        0xB9, 0x05, 0x00, 0x00, 0x00,

        // MOV ESI, host_str_addr (字符串地址)
        // 我们用 ESI 做指针
        0xBE,
        (host_str_addr & 0xFF),
        (host_str_addr >> 8) & 0xFF,
        (host_str_addr >> 16) & 0xFF,
        (host_str_addr >> 24) & 0xFF,

        // Label_Start:
        // MOV AL, byte ptr [ESI] (LODSB: AL = [ESI], ESI++)
        // 用 LODSB 比较方便，它自动取值并加 ESI
        0xAC,

        // MOV DL, AL (因为 INT 21/AH=02 需要字符在 DL)
        0x88, 0xC2, // MOV DL, AL

        // MOV AH, 0x02 (Service: Print Char)
        0xB4, 0x02,

        // INT 0x21 (Call DOS)
        0xCD, 0x21,

        // LOOP Label_Start (-9 bytes back)
        // LODSB(1) + MOV(2) + MOV(2) + INT(2) = 7 bytes
        // LOOP instruction itself is 2 bytes. 
        // Offset calculation: Jump back 7 bytes to LODSB.
        // 0xFE = -2, 0xF9 = -7
        0xE2, 0xF9,

        // INT 3 (Breakpoint/Exit)
        0xCC
    };

    memcpy(code_ptr, assembly, sizeof(assembly));

    // 4. 执行
    ctx.EIP = code_start_addr;

    // 我们多跑几步，因为有个循环
    // 5 chars * (LODSB+MOV+MOV+INT+LOOP = 5 instructions) = 25 steps
    printf("Output:\n ");
    runcpu(&ctx, 40);
    printf("\n");

    // =========================================================
    // 4. 结果验证
    // =========================================================
    printf("\n--- Verification ---\n");
    // 循环结束时 ECX 应该为 0
    printf("ECX: %d (Expected 0)\n", ctx.ECX.I32);
    // ESI 应该指向字符串末尾 (Start + 5)
    printf("ESI Offset: +%d (Expected +5)\n", ctx.ESI.I32 - host_str_addr);

    if (ctx.ECX.I32 == 0) {
        printf("[SUCCESS] Hello World printed via INT 21h!\n");
    }
    else {
        printf("[FAIL] Loop didn't finish correctly.\n");
    }

    free(raw_memory);
    return 0;
}