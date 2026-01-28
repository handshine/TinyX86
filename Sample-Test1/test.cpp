#include "pch.h"
#include "../TinyX86.h"
#include "../TinyX86.c"

extern "C" int ParseInstuction(uint8_t* buffer, uint32_t eip, DecodeContext* out_ctx) {
    (void)eip;
    if (!buffer || !out_ctx) {
        return -1;
    }
    *out_ctx = DecodeContext{};
    out_ctx->opcode = buffer[0];
    out_ctx->instr_len = 1;
    return 1;
}

extern "C" void FormatInstruction(uint8_t* buffer, DecodeContext* out_ctx) {
    (void)buffer;
    (void)out_ctx;
}

namespace {
DecodeContext MakeDecodeContext() {
    DecodeContext ctx{};
    ctx.pfx_op_size = 0;
    ctx.entry.op1 = NONE;
    ctx.entry.op2 = NONE;
    ctx.entry.op3 = NONE;
    return ctx;
}
}

TEST(CpuRegisterTests, ReadWriteGprHandlesSizesAndInvalid) {
    CPU_Context ctx{};

    EXPECT_TRUE(WriteGPR(&ctx, 0, 32, 0x12345678));
    EXPECT_EQ(0x12345678u, ReadGPR(&ctx, 0, 32));

    EXPECT_TRUE(WriteGPR(&ctx, 0, 16, 0xABCD));
    EXPECT_EQ(0xABCDu, ReadGPR(&ctx, 0, 16));

    EXPECT_TRUE(WriteGPR(&ctx, 4, 8, 0x12));
    EXPECT_EQ(0x12u, ReadGPR(&ctx, 4, 8));

    EXPECT_FALSE(WriteGPR(&ctx, 8, 32, 0x1));
    EXPECT_EQ(0u, ReadGPR(&ctx, 8, 32));
}

TEST(CpuAddressTests, GetEffectiveAddressHandlesSibAndDisp32) {
    CPU_Context ctx{};
    DecodeContext d_ctx = MakeDecodeContext();

    d_ctx.mod = 0;
    d_ctx.modrm = 5;
    d_ctx.rm = 5;
    d_ctx.disp = 0x20;
    d_ctx.has_sib = false;
    EXPECT_EQ(0x20u, GetEffectiveAddress(&ctx, &d_ctx));

    ctx.EAX.I32 = 0x1000;
    ctx.ECX.I32 = 3;
    d_ctx.has_sib = true;
    d_ctx.base = 0;
    d_ctx.index = 1;
    d_ctx.scale = 2;
    d_ctx.mod = 1;
    d_ctx.disp = 0x10;
    EXPECT_EQ(0x101Cu, GetEffectiveAddress(&ctx, &d_ctx));
}

TEST(CpuOperandTests, GetOperandValueReadsRegistersAndMemory) {
    CPU_Context ctx{};
    DecodeContext d_ctx = MakeDecodeContext();

    ctx.EAX.I32 = 0x11223344;
    d_ctx.entry.op1 = Gv;
    d_ctx.reg = 0;
    EXPECT_EQ(0x11223344u, GetOperandValue(&ctx, &d_ctx, 0));

    uint8_t memory[4] = { 0x7F, 0, 0, 0 };
    auto address = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(memory));
    d_ctx.entry.op1 = Eb;
    d_ctx.mod = 0;
    d_ctx.modrm = 5;
    d_ctx.rm = 5;
    d_ctx.disp = static_cast<int32_t>(address);
    d_ctx.has_sib = false;
    EXPECT_EQ(0x7Fu, GetOperandValue(&ctx, &d_ctx, 0));
}

TEST(CpuOperandTests, SetOperandValueWritesRegistersAndMemory) {
    CPU_Context ctx{};
    DecodeContext d_ctx = MakeDecodeContext();

    d_ctx.entry.op1 = OP_rAX;
    SetOperandValue(&ctx, &d_ctx, 0, 0x55667788);
    EXPECT_EQ(0x55667788u, ctx.EAX.I32);

    uint8_t memory[4] = { 0, 0, 0, 0 };
    auto address = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(memory));
    d_ctx.entry.op1 = Eb;
    d_ctx.mod = 0;
    d_ctx.modrm = 5;
    d_ctx.rm = 5;
    d_ctx.disp = static_cast<int32_t>(address);
    d_ctx.has_sib = false;
    SetOperandValue(&ctx, &d_ctx, 0, 0xAA);
    EXPECT_EQ(0xAAu, memory[0]);
}

TEST(CpuMoveTests, ExecMovRegImmWritesDestination) {
    CPU_Context ctx{};
    DecodeContext d_ctx = MakeDecodeContext();

    d_ctx.entry.op1 = OP_rAX;
    d_ctx.entry.op2 = Iv;
    d_ctx.imm = 0x12345678;

    Exec_MOV_Reg_Imm(&ctx, &d_ctx);
    EXPECT_EQ(0x12345678u, ctx.EAX.I32);
}

TEST(CpuFlagTests, CalcPfHandlesEvenParity) {
    EXPECT_EQ(1, CalcPF(0x00));
    EXPECT_EQ(0, CalcPF(0x01));
    EXPECT_EQ(1, CalcPF(0x03));
}

TEST(CpuFlagTests, UpdateEflagsHandlesAddAndLogic) {
    CPU_Context ctx{};
    // 初始化清零

        // --- Case 1: 8-bit ADD with Carry and Zero result ---
        // 0xFF (255/-1) + 0x01 (1) = 0x100 (256). Truncated to 8-bit: 0x00.
    UpdateEFLAGS(&ctx,
        0x100, 0xFF, 0x01, 8
        , ALU_ADD);

    EXPECT_EQ(
        1u, ctx.EFLAGS.CF); // 进位发生
    EXPECT_EQ(
        1u, ctx.EFLAGS.ZF); // 结果截断后为0
    EXPECT_EQ(
        0u, ctx.EFLAGS.OF); // 负+正不可能溢出

    // --- Case 2: 8-bit AND (Logic operation) ---
    // 0xAA (10101010) & 0x55 (01010101) = 0x00.
    // 逻辑运算应清除 CF/OF，并根据结果设置 ZF/SF/PF
    UpdateEFLAGS(&ctx,
        0x00, 0xAA, 0x55, 8
        , ALU_AND);

    EXPECT_EQ(
        0u, ctx.EFLAGS.CF); // 逻辑运算清除 CF
    EXPECT_EQ(
        0u, ctx.EFLAGS.OF); // 逻辑运算清除 OF
    EXPECT_EQ(
        1u, ctx.EFLAGS.ZF); // 结果为0，ZF应置位 (建议补充此断言)
}

TEST(CpuSizeTests, GetOperandBitSizeHonorsPrefixAndTypes) {
    CPU_Context ctx{};
    DecodeContext d_ctx = MakeDecodeContext();

    EXPECT_EQ(8, GetOperandBitSize(&ctx, &d_ctx, Eb));

    d_ctx.pfx_op_size = 0x66;
    EXPECT_EQ(16, GetOperandBitSize(&ctx, &d_ctx, Ev));

    d_ctx.pfx_op_size = 0;
    EXPECT_EQ(32, GetOperandBitSize(&ctx, &d_ctx, OP_rAX));
}

TEST(CpuAluTests, ExecAluGenericAddsAndCompares) {
    CPU_Context ctx{};
    DecodeContext d_ctx = MakeDecodeContext();

    ctx.EAX.I32 = 1;
    d_ctx.entry.op1 = Gv;
    d_ctx.entry.op2 = Iv;
    d_ctx.reg = 0;
    d_ctx.imm = 2;
    Exec_ALU_Generic(&ctx, &d_ctx, ALU_ADD, false);
    EXPECT_EQ(3u, ctx.EAX.I32);

    ctx.EAX.I32 = 5;
    d_ctx.imm = 5;
    Exec_ALU_Generic(&ctx, &d_ctx, ALU_CMP, true);
    EXPECT_EQ(5u, ctx.EAX.I32);
    EXPECT_EQ(1u, ctx.EFLAGS.ZF);
}

TEST(CpuAluTests, ExecGroup1SelectsOperationByReg) {
    CPU_Context ctx{};
    DecodeContext d_ctx = MakeDecodeContext();

    ctx.EAX.I32 = 1;
    d_ctx.entry.op1 = Gv;
    d_ctx.entry.op2 = Iv;
    d_ctx.reg = 0;
    d_ctx.imm = 4;
    Exec_Group1(&ctx, &d_ctx);
    EXPECT_EQ(5u, ctx.EAX.I32);
}

TEST(CpuStackTests, ExecPushWritesStackAndAdjustsEsp) {
    CPU_Context ctx{};
    DecodeContext d_ctx = MakeDecodeContext();

    uint8_t stack[8] = {};
    auto base = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(stack));
    ctx.ESP.I32 = base + 8;
    ctx.EAX.I32 = 0x12345678;

    d_ctx.entry.op1 = OP_rAX;
    Exec_PUSH(&ctx, &d_ctx);

    EXPECT_EQ(base + 4, ctx.ESP.I32);
    EXPECT_EQ(0x12345678u, *reinterpret_cast<uint32_t*>(ctx.ESP.I32));
}

TEST(CpuStackTests, ExecPopReadsStackAndWritesOperand) {
    CPU_Context ctx{};
    DecodeContext d_ctx = MakeDecodeContext();

    uint8_t stack[8] = {};
    auto base = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(stack));
    ctx.ESP.I32 = base;
    *reinterpret_cast<uint32_t*>(ctx.ESP.I32) = 0xAABBCCDD;

    d_ctx.entry.op1 = OP_rBX;
    Exec_POP(&ctx, &d_ctx);

    EXPECT_EQ(0xAABBCCDDu, ctx.EBX.I32);
    EXPECT_EQ(base + 4, ctx.ESP.I32);
}

TEST(CpuBranchTests, CheckConditionEvaluatesFlags) {
    CPU_Context ctx{};

    ctx.EFLAGS.ZF = 1;
    EXPECT_TRUE(CheckCondition(&ctx, 0x74));
    EXPECT_FALSE(CheckCondition(&ctx, 0x75));
}

TEST(CpuBranchTests, ExecBranchAdjustsEipWhenTaken) {
    CPU_Context ctx{};
    DecodeContext d_ctx = MakeDecodeContext();

    ctx.EIP = 100;
    d_ctx.instr_len = 2;
    d_ctx.imm = 5;
    EXPECT_TRUE(Exec_Branch(&ctx, &d_ctx, false));
    EXPECT_EQ(107u, ctx.EIP);

    ctx.EIP = 200;
    ctx.EFLAGS.ZF = 0;
    d_ctx.opcode = 0x74;
    d_ctx.imm = 10;
    EXPECT_FALSE(Exec_Branch(&ctx, &d_ctx, true));
    EXPECT_EQ(200u, ctx.EIP);
}

TEST(CpuBranchTests, ExecCallPushesReturnAndUpdatesEip) {
    CPU_Context ctx{};
    DecodeContext d_ctx = MakeDecodeContext();

    uint8_t stack[8] = {};
    auto base = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(stack));
    ctx.ESP.I32 = base + 8;
    ctx.EIP = 100;
    d_ctx.instr_len = 5;
    d_ctx.imm = 3;

    EXPECT_TRUE(Exec_CALL(&ctx, &d_ctx));
    EXPECT_EQ(base + 4, ctx.ESP.I32);
    EXPECT_EQ(105u, *reinterpret_cast<uint32_t*>(ctx.ESP.I32));
    EXPECT_EQ(108u, ctx.EIP);
}

TEST(CpuBranchTests, ExecRetRestoresEipAndStack) {
    CPU_Context ctx{};
    DecodeContext d_ctx = MakeDecodeContext();

    uint8_t stack[12] = {};
    auto base = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(stack));
    ctx.ESP.I32 = base;
    *reinterpret_cast<uint32_t*>(ctx.ESP.I32) = 0xDEADBEEF;
    d_ctx.opcode = 0xC2;
    d_ctx.imm = 4;

    EXPECT_TRUE(Exec_RET(&ctx, &d_ctx));
    EXPECT_EQ(0xDEADBEEFu, ctx.EIP);
    EXPECT_EQ(base + 8, ctx.ESP.I32);
}

TEST(CpuIncDecTests, ExecIncAndDecAdjustRegisters) {
    CPU_Context ctx{};
    DecodeContext d_ctx = MakeDecodeContext();

    ctx.EAX.I32 = 1;
    d_ctx.opcode = 0x40;
    Exec_INC(&ctx, &d_ctx);
    EXPECT_EQ(2u, ctx.EAX.I32);

    d_ctx.opcode = 0x48;
    Exec_DEC(&ctx, &d_ctx);
    EXPECT_EQ(1u, ctx.EAX.I32);
}

TEST(CpuFlagTests, UpdateLogicFlagsSetsZfSfPf) {
    CPU_Context ctx{};

    UpdateLogicFlags(&ctx, 0, 8);
    EXPECT_EQ(1u, ctx.EFLAGS.ZF);
    EXPECT_EQ(0u, ctx.EFLAGS.SF);
    EXPECT_EQ(1u, ctx.EFLAGS.PF);
}

TEST(CpuShiftTests, ExecGroup2ShiftLeftUpdatesFlags) {
    CPU_Context ctx{};
    DecodeContext d_ctx = MakeDecodeContext();

    ctx.EAX.I32 = 0x80000001;
    d_ctx.entry.op1 = Ev;
    d_ctx.reg = 4;
    d_ctx.opcode = 0xD1;
    d_ctx.mod = 3;
    d_ctx.rm = 0;

    Exec_Group2(&ctx, &d_ctx);
    EXPECT_EQ(0x00000002u, ctx.EAX.I32);
    EXPECT_EQ(1u, ctx.EFLAGS.CF);
    EXPECT_EQ(1u, ctx.EFLAGS.OF);
}

TEST(CpuGroup3Tests, GetGroup3SourceSelectsOperand) {
    CPU_Context ctx{};
    DecodeContext d_ctx = MakeDecodeContext();

    ctx.EAX.I32 = 0x34;
    d_ctx.entry.op1 = Eb;
    d_ctx.entry.op2 = Ib;
    d_ctx.mod = 3;
    d_ctx.rm = 0;
    d_ctx.imm = 0x12;

    d_ctx.reg = 4;
    EXPECT_EQ(0x12u, GetGroup3Source(&ctx, &d_ctx));

    d_ctx.reg = 2;
    EXPECT_EQ(0x34u, GetGroup3Source(&ctx, &d_ctx));
}

TEST(CpuGroup3Tests, SetGroup3DestWritesOperand) {
    CPU_Context ctx{};
    DecodeContext d_ctx = MakeDecodeContext();

    d_ctx.entry.op1 = OP_rAX;
    SetGroup3Dest(&ctx, &d_ctx, 0x55);
    EXPECT_EQ(0x55u, ctx.EAX.I32);
}

TEST(CpuGroup3Tests, ExecGroup3NotAndMulBehave) {
    CPU_Context ctx{};
    DecodeContext d_ctx = MakeDecodeContext();

    ctx.EAX.I32 = 0x0F0F0F0F;
    d_ctx.entry.op1 = Ev;
    d_ctx.mod = 3;
    d_ctx.rm = 0;
    d_ctx.reg = 2;
    Exec_Group3(&ctx, &d_ctx);
    EXPECT_EQ(0xF0F0F0F0u, ctx.EAX.I32);

    ctx.EAX.I32 = 0x03;
    ctx.ECX.I32 = 0x04;
    d_ctx.entry.op1 = OP_AL;
    d_ctx.entry.op2 = Eb;
    d_ctx.mod = 3;
    d_ctx.rm = 1;
    d_ctx.reg = 4;
    Exec_Group3(&ctx, &d_ctx);
    EXPECT_EQ(12u, ctx.EAX.I16);
    EXPECT_EQ(0u, ctx.EFLAGS.CF);
}

TEST(CpuExecutionTests, ExecuteInstructionHandlesNop) {
    CPU_Context ctx{};
    DecodeContext d_ctx = MakeDecodeContext();

    d_ctx.opcode = 0x90;
    EXPECT_FALSE(ExecuteInstruction(&ctx, &d_ctx));
}

TEST(CpuExecutionTests, RunCpuExecutesSingleInstruction) {
    CPU_Context ctx{};
    uint8_t program[] = { 0x90 };
    ctx.EIP = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(program));

    EXPECT_EQ(0, runcpu(&ctx, 1));
    EXPECT_EQ(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(program)) + 1, ctx.EIP);
}
