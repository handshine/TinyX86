#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <time.h>
#include <windows.h>
#include <tchar.h>
#define MAX_PATH 260  // Windows最大路径长度
#define MessageBoxAAddr 0x77D507EA

#ifdef __cplusplus
extern "C" {
#endif
// 定义一个全局缓冲区和追加函数，减少代码变动
 char tempBuf[512];
//宏处理类printf逻辑，用于格式化输出到缓冲区
#define APPEND(...) { \
    sprintf(tempBuf, __VA_ARGS__); \
    /* 1. 检查这里是否需要将 \n 换成 \r\n */ \
    /* 2. 使用更安全的追加方式（可选） */ \
    strcat(pOutBuffer, tempBuf); \
    strcat(pOutBuffer, "\r\n"); \
}


//**************************************************************************
// PE文件操作相关函数声明
//**************************************************************************

// 将PE文件读取到缓冲区
// lpszFile: 文件路径
// ppFileBuffer: 缓冲区指针的指针
// 返回值: 成功返回文件大小，失败返回0
    DWORD ReadPEFile(IN LPCTSTR lpszFile, OUT LPVOID* ppFileBuffer);

// 打印PE文件头信息
// pBuffer: 缓冲区指针
// bufferName: 缓冲区名称
VOID PrintPEHeaders(IN LPVOID pBuffer, IN LPCSTR bufferName);

typedef struct _PEHeaderInfo {
    // --- 左侧列字段 ---
    DWORD dwEntryPoint;              // 入口点 (AddressOfEntryPoint)
    DWORD dwImageBase;               // 镜像基址 (ImageBase)
    DWORD dwSizeOfImage;             // 镜像大小 (SizeOfImage)
    DWORD dwBaseOfCode;              // 代码基址 (BaseOfCode)
    DWORD dwBaseOfData;              // 数据基址 (BaseOfData)
    DWORD dwSectionAlignment;        // 内存对齐 (SectionAlignment)
    DWORD dwFileAlignment;          // 文件对齐 (FileAlignment)
    WORD  wMagic;                    // 标志字/魔数 (Magic)

    // --- 右侧列字段 ---
    WORD  wSubsystem;                // 子系统 (Subsystem)
    WORD  wNumberOfSections;         // 区段数目 (NumberOfSections)
    DWORD dwTimeDateStamp;           // 时间戳 (TimeDateStamp)
    DWORD dwSizeOfHeaders;           // PE头大小 (SizeOfHeaders)
    WORD  wCharacteristics;          // 特征值 (Characteristics)
    DWORD dwCheckSum;                // 校验和 (CheckSum)
    WORD  wSizeOfOptionalHeader;     // 可选PE头大小 (SizeOfOptionalHeader)
    DWORD dwNumberOfRvaAndSizes;     // 目录项数目 (NumberOfRvaAndSizes)

} PEHeaderInfo, * PPEHeaderInfo;

// 解析PE文件头信息, 输入缓冲区指针和数据结构体指针，填充PEHeaderInfo结构体
VOID ParsePEHeaders(IN LPVOID pBuffer, IN PPEHeaderInfo pHeaderInfo);

// 将FileBuffer复制到ImageBuffer（按内存对齐方式展开）
// pFileBuffer: FileBuffer指针
// ppImageBuffer: ImageBuffer指针的指针
// 返回值: 成功返回ImageBuffer大小，失败返回0
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* ppImageBuffer);

// 将ImageBuffer压缩回FileBuffer（按文件对齐方式）
// pImageBuffer: ImageBuffer指针
// ppNewBuffer: 新FileBuffer指针的指针
// 返回值: 成功返回FileBuffer大小，失败返回0
DWORD CopyImageBufferToFileBuffer(IN LPVOID pImageBuffer, OUT LPVOID* ppNewBuffer);

// 将内存数据写入文件
// pMemBuffer: 内存数据指针
// size: 数据大小
// lpszFile: 目标文件路径
// 返回值: 成功返回写入大小，失败返回0
DWORD MemoryToFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPCSTR lpszFile);

// 验证PE文件的有效性
// pFileBuffer: 文件缓冲区指针
// 返回值: 有效返回TRUE，无效返回FALSE
BOOL ValidatePEFile(IN LPVOID pFileBuffer);

// 将RVA转换为文件偏移（FOA）
// pImageBuffer: ImageBuffer指针
// dwRva: RVA值
// 返回值: 成功返回FOA值，失败返回0
DWORD RvaToFileOffset(IN LPVOID pFileBuffer, IN DWORD dwRva);

// 在指定位置注入ShellCode
// pFileBuffer: FileBuffer指针
// pShellCode: ShellCode数据指针
// dwShellCodeSize: ShellCode大小
// dwInjectRVA: 注入位置的RVA
// dwInjectFileOffset: 注入位置的文件偏移
// 返回值: 成功返回1，失败返回0
DWORD AddCode(IN PVOID pFileBuffer, IN PVOID pShellCode, IN DWORD dwShellCodeSize, IN DWORD dwInjectRVA, IN DWORD dwInjectFileOffset);

// 添加新节（可读可写可执行）
// pFileBuffer: FileBuffer指针
// OriginalFileSize: 原始文件大小
// ppNewFileBuffer: 新FileBuffer指针的指针
// pdwNewRVA: 新节的RVA的指针,NULL表示不需要返回
// pdwNewFileOffset: 新节的文件偏移的指针，NULL表示不需要返回
// 返回值: 成功返回新文件大小，失败返回0
DWORD AddSection(IN LPVOID pFileBuffer, IN DWORD OriginalFileSize, OUT LPVOID* ppNewFileBuffer, OUT LPDWORD pdwNewRVA, OUT LPDWORD pdwNewFileOffset);

// 扩展最后一个节的大小
// pFileBuffer: FileBuffer指针
// OriginalFileSize: 原始文件大小
// ppNewFileBuffer: 新FileBuffer指针的指针
// pdwNewRVA: 扩展空间的RVA的指针
// pdwNewFileOffset: 扩展空间的文件偏移的指针
// 返回值: 成功返回新文件大小，失败返回0
DWORD ExpandLastSection(IN LPVOID pFileBuffer, IN DWORD OriginalFileSize, OUT LPVOID* ppNewFileBuffer, OUT LPDWORD pdwNewRVA, OUT LPDWORD pdwNewFileOffset);

// 合并所有节
// pImageBuffer: ImageBuffer指针
// ppNewFileBuffer: 新FileBuffer指针的指针
// 返回值: 成功返回新文件大小，失败返回0
DWORD MergeSections(IN LPVOID pImageBuffer, OUT LPVOID* ppNewFileBuffer);

// 数据对齐
// data: 待对齐的数据
// alignment: 对齐粒度
// 返回值: 对齐后的值
DWORD Align(IN DWORD data, IN DWORD alignment);


// Print数据目录信息
void PrintDataDirectory(IN LPVOID pBuffer);

// Print导出表信息
void PrintExportTable(IN LPVOID pBuffer);
//Get导出表信息到缓冲区
void GetExportTableStrings(IN LPVOID pBuffer, OUT char* pOutBuffer);

// 导出表--通过函数名获取函数地址RVA
DWORD GetFunctionAddrByName(IN LPVOID pBuffer, IN PCSTR FunctionName);

// 导出表--通过函数序号获取函数地址RVA
DWORD GetFunctionAddrByOrdinals(IN LPVOID pBuffer, IN WORD Ordinal);

//Print重定位表信息
void PrintRelocTable(IN LPVOID pFileBuffer);

//移动导出表到新位置
void MoveExportTable(IN LPVOID pFileBuffer, IN DWORD FileSize, IN LPVOID* ppNewBuffer, IN DWORD NewExportRVA, IN DWORD NewExportFOA);

//移动重定位表到新位置
void MoveRelocTable(IN LPVOID pFileBuffer, IN DWORD FileSize, IN LPVOID* ppNewBuffer, IN DWORD NewRelocRVA, IN DWORD NewRelocFOA);

//修改ImageBase值
//返回旧ImageBase值
DWORD ChangeImageBase(LPVOID pBuffer, DWORD NewImageBase);

//在imagebase修改后，修正重定位表中的重定位项
void FixRelocEntries(IN LPVOID pFileBuffer, IN DWORD OldImageBase, IN DWORD NewImageBase, IN DWORD NewRelocRVA, IN DWORD NewRelocFOA);

//打印导入表信息
void PrintImportTable(IN LPVOID pFileBuffer);
//Get导入表信息到缓冲区
void GetImportTableStrings(IN LPVOID pFileBuffer, OUT char* pOutBuffer);
//GetIAT表信息到缓冲区
void GetIATTableStrings(IN LPVOID pFileBuffer, OUT char* pOutBuffer);

//打印绑定导入表信息
void PrintBoundImportTable(IN LPVOID pFileBuffer);
//Get绑定导入表信息到缓冲区
void GetBoundImportTableStrings(IN LPVOID pFileBuffer, OUT char* pOutBuffer);

//导入DLL注入
void DllImportInjection(IN PVOID pFileBuffer,IN DWORD NewImportRVA);

//代码段,在Imagebuffer拉伸状态下查询返回，返回代码段有效数据大小和RVA
DWORD QueryCodeSection(IN PVOID pImageBuffer, OUT PVOID *ppCodeRVA);

//资源表资源遍历打印
void PrintResourceTable(IN LPVOID pFileBuffer);
//Get资源表信息到缓冲区
void GetResourceTableStrings(IN LPVOID pFileBuffer, OUT char* pOutBuffer);


#ifdef __cplusplus
}
#endif
