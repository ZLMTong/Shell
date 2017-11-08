#pragma once
// ʹ�ø�ѹ���������Ҫ����3������Ԥ����ָ��
#define ZLIB_WINAPI
#include "zlib/zlib.h"
#pragma comment(lib,"zlib/zlibstat.lib")

typedef struct _PACKINFO
{
	void* StartAddreass;		//��ʼ������ַ
	void* TargetOep;			//Ŀ�����OEP
	uLong CompressSize;			//ѹ����ĳ���
	uLong UnCompressSize;		//ѹ��ǰ�ĳ���
	PBYTE bCompress;			//���ѹ������ֽڵĻ�������ַ
	DWORD dwOldINTRva;			//�ɵ�INT��RVA
	DWORD dwOldRelocRva;		//�ɵ��ض�λ���RVA
	DWORD dwOldRelocSize;		//�ɵ��ض�λ���size
}PACKINFO, *PPACKINFO;

//�ض�λ�ṹ��
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