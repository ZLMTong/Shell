#pragma once
// 使用该压缩库包含需要下面3条编译预处理指令
#define ZLIB_WINAPI
#include "zlib/zlib.h"
#pragma comment(lib,"zlib/zlibstat.lib")

typedef struct _PACKINFO
{
	void* StartAddreass;		//起始函数地址
	void* TargetOep;			//目标程序OEP
	uLong CompressSize;			//压缩后的长度
	uLong UnCompressSize;		//压缩前的长度
	PBYTE bCompress;			//存放压缩后的字节的缓冲区地址
	DWORD dwOldINTRva;			//旧的INT的RVA
	DWORD dwOldRelocRva;		//旧的重定位表的RVA
	DWORD dwOldRelocSize;		//旧的重定位表的size
}PACKINFO, *PPACKINFO;

//重定位结构体
typedef struct _RELOCTYPE {
	unsigned short offset : 12;
	unsigned short type : 4;
}RELOCTYPE, *PRELOCTYPE;

typedef FARPROC(WINAPI *MYGETPROCADDRESS)
(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);

typedef HMODULE(WINAPI *MYLOADLIBRARY)
(_In_ LPCSTR lpLibFileName);

typedef HMODULE(WINAPI *MYGETMODULEHANDLEA)
(_In_ LPCSTR lpModuleName);


typedef LPVOID(WINAPI *MYVIRTUALALLOC)(
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect
	);

typedef BOOL(WINAPI *MYVIRTUALFREE)(
	_Pre_notnull_ _When_(dwFreeType == MEM_DECOMMIT, _Post_invalid_) _When_(dwFreeType == MEM_RELEASE, _Post_ptr_invalid_) LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD dwFreeType
	);

typedef BOOL(WINAPI *MYVIRTUALPROTECT)(
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flNewProtect,
	_Out_ PDWORD lpflOldProtect
	);

void MyGetProcAddress(LPVOID *pGetProc, LPVOID *pLoadLibrary);
void Init();
void Decode();
void Uncompress();
void Start();
void FixIAT();
void FixSrcReloc();
LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
int  Password();