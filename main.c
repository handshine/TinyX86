#include "TinyX86.h"

// ============================================================================
// Main
// ============================================================================

int main() {
    // 1. 初始化内存
    uint32_t stack_size = 1024 * 64;
    // 我们申请一大块内存，既做代码段也做栈
    // 假设 Base = 0x400000 (模拟 exe 加载基址)
    uint8_t* raw_memory = (uint8_t*)malloc(stack_size);
    if (!raw_memory) return -1;
    memset(raw_memory, 0, stack_size);

    // 为了让地址好看点，我们不动 raw_memory 指针，但在使用 ctx->EIP 时要注意
    // 简单起见，我们假设 host_addr = guest_addr (Host Passthrough)

    CPU_Context ctx;
    memset(&ctx, 0, sizeof(ctx));

    // 栈底设在内存末尾
    uint32_t mem_base = (uint32_t)(uintptr_t)raw_memory;
    ctx.ESP.I32 = mem_base + stack_size - 1024;

    // 2. 注入测试代码 (Sprint 11 的 FPU + 简单的 CALL 测试)
    uint32_t code_entry = mem_base + 0x100;
    uint8_t* code_ptr = raw_memory + 0x100;

    // 准备 FPU 数据
    float f_val = 1.5f;
    memcpy(raw_memory, &f_val, 4); // Mem[0] = 1.5

    /* 构造一段复杂的测试代码：
       0:  D9 05 ...       FLD dword ptr [base]  (Load 1.5)
       6:  D8 C0           FADD ST0, ST0         (1.5 + 1.5 = 3.0)
       8:  E8 05 00 00 00  CALL func             (Step Over 测试)
       D:  90              NOP                   (断点停在这里)
       E:  CC              INT 3                 (结束)

       func: (Offset +0x12)
       12: B8 88 00 00 00  MOV EAX, 0x88
       17: C3              RET
    */

    // 写入数据地址
    uint8_t data_addr_bytes[4];
    memcpy(data_addr_bytes, &mem_base, 4);

    uint8_t code[] = {
        // FLD dword ptr [mem_base] (6 bytes)
        0xD9, 0x05, data_addr_bytes[0], data_addr_bytes[1], data_addr_bytes[2], data_addr_bytes[3],

        // FADD ST0, ST0 (2 bytes)
        0xD8, 0xC0,

        // --- 修复点 ---
        // CALL +2 (跳转到 index 15) 
        // Current Offset=8, Len=5, Next=13. Target=15. Offset = 15-13 = 2.
        0xE8, 0x02, 0x00, 0x00, 0x00,

        0x90, // NOP (Ret addr, index 13)
        0xCC, // INT 3 (index 14)

        // Func starts here (index 15):
        0xB8, 0x88, 0x00, 0x00, 0x00, // MOV EAX, 0x88
        0xC3  // RET
    };
    memcpy(code_ptr, code, sizeof(code));
    ctx.EIP = code_entry;

    // 3. 启动调试器
    Debugger(&ctx);

    free(raw_memory);
    return 0;
}
