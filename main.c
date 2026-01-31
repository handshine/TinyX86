#include "TinyX86.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h> // 需要 malloc

int main() {
    printf("--- Sprint 7: Stack Frame & Pointers Test (Safe Memory) ---\n");

    // =========================================================
    // 1. 内存分配 (模拟 RAM)
    // =========================================================
    // 申请 64KB 内存作为模拟器的可用空间
    // 你的 MemRead 是直接解引用，所以必须给它合法的宿主指针
    uint32_t stack_size = 1024 * 64;
    uint8_t* raw_memory = (uint8_t*)malloc(stack_size);
    if (!raw_memory) {
        printf("[Fatal] Host memory allocation failed.\n");
        return -1;
    }

    // 初始化内存为 0CC (Int 3 中断码，方便调试溢出)
    memset(raw_memory, 0xCC, stack_size);

    // =========================================================
    // 2. 环境初始化
    // =========================================================
    CPU_Context ctx;
    memset(&ctx, 0, sizeof(ctx));

    // 设置栈顶 (ESP) 指向内存块的末尾 (预留一点缓冲区)
    // 注意：我们将宿主的 64位指针强转为 32位 (假设我们编译为 x86 32位程序，或者地址在低4GB)
    // 如果是 x64 编译，强转可能会截断，但作为测试 demo 暂时接受
    uint32_t stack_bottom = (uint32_t)(uintptr_t)(raw_memory + stack_size - 1024);

    ctx.ESP.I32 = stack_bottom;
    ctx.EBP.I32 = stack_bottom; // 初始 EBP = ESP

    printf("Memory Allocated at Host Address: 0x%p\n", raw_memory);
    printf("Initial ESP set to: 0x%08X\n", ctx.ESP.I32);

    // =========================================================
    // 3. 准备机器码
    // =========================================================
    // 模拟 void swap_local() { int a, b; swap(&a, &b); }
    uint8_t code[] = {
        // [0] ENTER 8, 0 (分配8字节局部变量)
        0xC8, 0x08, 0x00, 0x00,

        // [4] MOV DWORD PTR [EBP-4], 0xAAAAAAAA
        0xC7, 0x45, 0xFC, 0xAA, 0xAA, 0xAA, 0xAA,

        // [11] MOV DWORD PTR [EBP-8], 0xBBBBBBBB
        0xC7, 0x45, 0xF8, 0xBB, 0xBB, 0xBB, 0xBB,

        // [18] LEA EAX, [EBP-4] (获取变量 a 的地址)
        0x8D, 0x45, 0xFC,

        // [21] LEA EBX, [EBP-8] (获取变量 b 的地址)
        0x8D, 0x5D, 0xF8,

        // [24] XCHG ECX, [EAX] (模拟 swap 的一部分)
        // 先把 [EAX] 读入 ECX，再写回... 为了演示 XCHG，我们换一种写法：
        // 假设我们只是把 EAX 和 EBX 指向的内容交换，这里为了简单测试指令逻辑：
        // 1. ECX = [EAX] (读 a)
        0x8B, 0x08,
        // 2. XCHG ECX, [EBX] (ECX 变成 b, [EBX] 变成 a)
        0x87, 0x0B,
        // 3. MOV [EAX], ECX (b 写入 [EAX])
        0x89, 0x08,

        // [30] LEAVE (恢复栈)
        0xC9,

        // [31] 结束标记
        0x90
    };

    // 设置 EIP
    ctx.EIP = (uint32_t)(uintptr_t)code;

    // =========================================================
    // 4. 执行
    // =========================================================
    // 运行 10 条指令 (涵盖 ENTER, LEA, XCHG, LEAVE)
    runcpu(&ctx, 10);

    // =========================================================
    // 5. 验证结果
    // =========================================================
    printf("\n--- Verification ---\n");
    printf("Final ESP: 0x%08X (Expected: 0x%08X)\n", ctx.ESP.I32, stack_bottom);
    printf("Final EBP: 0x%08X (Expected: 0x%08X)\n", ctx.EBP.I32, stack_bottom);

    // 验证内存交换
    // 变量 A 原地址: 栈底(Stack Bottom) - 4 (Old EBP) - 4 (Var A) = Bottom - 8
    // 变量 B 原地址: 栈底(Stack Bottom) - 4 (Old EBP) - 8 (Var B) = Bottom - 12
    // 注意：ENTER 指令先把 Old EBP 压栈 (ESP-=4)，然后 ESP-=8

    // 计算变量在宿主内存中的真实地址
    uint32_t addr_a = stack_bottom - 8;
    uint32_t addr_b = stack_bottom - 12;

    // 直接读取宿主内存（因为 MemRead 也是这么干的）
    uint32_t val_a = *(uint32_t*)addr_a;
    uint32_t val_b = *(uint32_t*)addr_b;

    printf("Var A (at 0x%08X): 0x%08X (Expected: 0xBBBBBBBB)\n", addr_a, val_a);
    printf("Var B (at 0x%08X): 0x%08X (Expected: 0xAAAAAAAA)\n", addr_b, val_b);

    int success = 1;
    if (ctx.ESP.I32 != stack_bottom) success = 0;
    if (val_a != 0xBBBBBBBB || val_b != 0xAAAAAAAA) success = 0;

    if (success) {
        printf("\n[SUCCESS] Memory safe stack test passed.\n");
    }
    else {
        printf("\n[FAIL] Logic error detected.\n");
    }

    // 释放内存
    free(raw_memory);
    return 0;
}