// Stub.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "stub.h"
#include "windows.h"
#include <corecrt_malloc.h>




#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
#pragma comment(linker,"/section:.text,RWE")
#pragma comment(linker,"/section:.idata,RWE")
// #pragma comment(linker,"/section:.rsrc,RWE")
// #pragma comment(linker,"/section:.reloc,RWE")


extern "C" _declspec(dllexport) PACKINFO g_PackInfo = { (void*)Start };



MYGETPROCADDRESS g_GetProcAddress = nullptr;
MYLOADLIBRARY g_LoadLibraryA = nullptr;
MYGETMODULEHANDLEA g_GetModuleHandleA = nullptr;
MYVIRTUALALLOC g_VirtualAlloc = nullptr;
MYVIRTUALFREE g_VirtualFree = nullptr;
MYVIRTUALPROTECT g_VirtualProtect = nullptr;


_declspec(naked) void Start()
{
	_asm {
		PUSH EBP
		MOV EBP, ESP
		PUSH - 1
		PUSH 415448
		PUSH 402148					// 在这段代码中类似这样的操作数可以乱填      
		MOV EAX, DWORD PTR FS : [0]
		PUSH EAX
		MOV DWORD PTR FS : [0], ESP
		ADD ESP, 6
		PUSH EBX
		PUSH ESI
		PUSH EDI
		ADD BYTE PTR DS : [EAX], AL // 这条指令可以不要
		jmp hua
		hua :
		call Init;
		jmp emp1;
		_emit 0x09;
	emp1:
		mov eax, dword ptr fs : [0x30]//检测是否被调试
			mov al, byte ptr[eax + 2]
			cmp al, 0
			je ep;
			push 0
			call ExitProcess
			ep :
		call Password;

	}
}


void MyGetProcAddress(LPVOID *pGetProc, LPVOID *pLoadLibrary)
{
	PCHAR pBuf = NULL;
	_asm
	{
		mov eax, fs:[0x30];		//找到PEB
		mov eax, [eax + 0x0C];	//找到了LDR
		mov eax, [eax + 0x0C];	//找到了第一个节点
		mov eax, [eax];			//找到了ntdll
		mov eax, [eax];			//找到了kernel32.dll
		mov ebx, dword ptr ds : [eax + 0x18];
		mov pBuf, ebx;
	}
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
	//数据目录表
	PIMAGE_DATA_DIRECTORY pExportDir =
		(pNt->OptionalHeader.DataDirectory + 0);
	//导出表
	PIMAGE_EXPORT_DIRECTORY pExport =
		(PIMAGE_EXPORT_DIRECTORY)(pExportDir->VirtualAddress + pBuf);
	//1  找到三个表：名称，地址，序号
	//地址表
	PDWORD pExpAddr = (PDWORD)(pExport->AddressOfFunctions + pBuf);
	//名称表
	PDWORD pExpName = (PDWORD)(pExport->AddressOfNames + pBuf);
	//序号表
	PWORD pExpOrd = (PWORD)(pExport->AddressOfNameOrdinals + pBuf);
	PVOID pGetProcAddress = 0;
	PVOID pLoadLibry = 0;
	//2  在名称表中去遍历GetProcAddress这个字符串
	for (int i = 0; i < pExport->NumberOfNames; i++)
	{
		char* pName = (pExpName[i] + pBuf);
		if (strcmp(pName, "GetProcAddress") == 0)
		{
			pGetProcAddress = pExpAddr[pExpOrd[i]] + pBuf;
		}
		if (strcmp(pName, "LoadLibraryA") == 0)
		{
			pLoadLibry = pExpAddr[pExpOrd[i]] + pBuf;
		}
	}
	*pGetProc = pGetProcAddress;
	*pLoadLibrary = pLoadLibry;
}

//入口点
void Init()
{
	MyGetProcAddress((LPVOID*)&g_GetProcAddress, (LPVOID*)&g_LoadLibraryA);
	g_GetModuleHandleA = (MYGETMODULEHANDLEA)g_GetProcAddress(g_LoadLibraryA("kernel32.dll"), "GetModuleHandleA");
	g_VirtualAlloc = (MYVIRTUALALLOC)g_GetProcAddress(g_GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
	g_VirtualFree = (MYVIRTUALFREE)g_GetProcAddress(g_GetModuleHandleA("kernel32.dll"), "VirtualFree");
	g_VirtualProtect = (MYVIRTUALPROTECT)g_GetProcAddress(g_GetModuleHandleA("kernel32.dll"), "VirtualProtect");
}

//解密
void Decode()
{
	PCHAR pBuf = (PCHAR)g_GetModuleHandleA(NULL);
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_SECTION_HEADER pSecond = pSection;
	for (int i = 0; i <= pNt->FileHeader.NumberOfSections; i++)
	{
		if (strcmp(".text", (char*)pSection[i].Name) == 0)
		{
			pSecond = pSection + i;
		}
	}

	PCHAR pStart = (pSecond->VirtualAddress + pBuf);
	for (int i = 0; i < pSecond->Misc.VirtualSize; i++)
	{
		pStart[i] ^= 0x15;
	}
}

void Uncompress()
{
	//判断是否解压缩
	if (!g_PackInfo.CompressSize || !g_PackInfo.UnCompressSize)
	{
		return;
	}

	PCHAR pBuf = (PCHAR)g_GetModuleHandleA(NULL);
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	//代码段地址
	PCHAR pStart = pSection->VirtualAddress + pBuf;
	//申请空间存放解压后的代码
	PBYTE pUnCompressSize = (PBYTE)g_VirtualAlloc(NULL, g_PackInfo.UnCompressSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pUnCompressSize == NULL) return;

	//改变代码段读写属性，保证可读写
	DWORD dwOldProt = 0;
	g_VirtualProtect(pStart, 0x4e00, PAGE_EXECUTE_READWRITE, &dwOldProt);

	//解压缩
	// pUnCompressSize  存放解压缩后的缓冲区地址
	// nUnComLen		解压后的字节数
	// pStart			要解压的缓冲区地址
	// g_PackInfo.CompressSize	要解压的长度
	if (uncompress((PBYTE)pUnCompressSize, &g_PackInfo.UnCompressSize, (PBYTE)pStart, g_PackInfo.CompressSize) != Z_OK) {
		//解压失败,释放空间*
		g_VirtualFree(pUnCompressSize, 0, MEM_RELEASE);
		return;
	}
	//解压成功
	memcpy(pStart, pUnCompressSize, g_PackInfo.UnCompressSize);
	//修改区段属性
	g_VirtualProtect(pStart, 0x4e00, PAGE_EXECUTE_READWRITE, &dwOldProt);
	//代码段大小给改回来
	//保证可写
	g_VirtualProtect(pSection, 16, PAGE_READWRITE, &dwOldProt);
	//修改区段大小
	pSection->SizeOfRawData = g_PackInfo.UnCompressSize;
	g_VirtualProtect(pSection, 16, dwOldProt, &dwOldProt);
}

//修复重定位
void FixSrcReloc()
{
	// 找到原重定位表信息的地址
	HMODULE hBase = g_GetModuleHandleA(0);
	//默认加载基址
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)hBase + pDos->e_lfanew);
	// 减去默认加载基址
	DWORD dwImageBase = 0x400000;
	//是否有重定位信息
	if (!g_PackInfo.dwOldRelocRva || !g_PackInfo.dwOldRelocSize) {
		return;
	}
	//找到要重定位的数据
	PIMAGE_BASE_RELOCATION  pRelocAddr = (PIMAGE_BASE_RELOCATION)((DWORD)hBase + g_PackInfo.dwOldRelocRva);
	DWORD dwCount = 0;
	while (pRelocAddr->VirtualAddress && dwCount < g_PackInfo.dwOldRelocSize) {
		// 重定位块数组的起始地址
		PRELOCTYPE pOffSetArr = (PRELOCTYPE)(pRelocAddr + 1);
		// 数组成员个数
		DWORD dwCount = (pRelocAddr->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOCTYPE);
		for (DWORD i = 0; i < dwCount; ++i) {
			if (pOffSetArr[i].type == 3) {
				//要重定位的数据的RVA
				DWORD dwOffset = pOffSetArr[i].offset + pRelocAddr->VirtualAddress;
				//要重定位的数据的VA
				PDWORD pAddr = (PDWORD)((DWORD)hBase + dwOffset);
				//保证可写
				DWORD dwOldProtect = 0;
				if (!g_VirtualProtect(pAddr, 4, PAGE_READWRITE, &dwOldProtect)) return;
				/*修复该值
				修复后的值 = 修复前的值 - dwImageBase + hBase*/
				*pAddr = *pAddr - dwImageBase + (DWORD)hBase;
				if (!g_VirtualProtect(pAddr, 4, dwOldProtect, &dwOldProtect)) return;

			}
		}
		// 已重定位数据大小
		dwCount += pRelocAddr->SizeOfBlock;
		// 定位到下一个区块
		pRelocAddr = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocAddr + pRelocAddr->SizeOfBlock);
	}
}

void FixIAT() {
	/* 获取INT的地址 */
	DWORD dwRva = g_PackInfo.dwOldINTRva;
	HMODULE hBase = g_GetModuleHandleA(0);
	PIMAGE_IMPORT_DESCRIPTOR pImp = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hBase + dwRva);
	/*修复导入表*/
	while (pImp->Name) {
		/*导入DLL*/
		PCHAR pDllName = (PCHAR)((DWORD)hBase + pImp->Name);
		HMODULE hDll = g_LoadLibraryA(pDllName);
		/*获取名称数组起始地址和地址数组起始地址*/
		PIMAGE_THUNK_DATA pArrFunName = (PIMAGE_THUNK_DATA)((DWORD)hBase + pImp->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pArrFunAddr = (PIMAGE_THUNK_DATA)((DWORD)hBase + pImp->FirstThunk);
		/*根据名字/序号获取函数地址，存入对应的地址数组内*/
		DWORD dwCount = 0;
		while (pArrFunName->u1.Ordinal) {
			/*该变量用于存放找到的函数地址*/
			DWORD dwFunAddr = 0;
			if (IMAGE_SNAP_BY_ORDINAL(pArrFunName->u1.Ordinal)) {
				dwFunAddr = (DWORD)g_GetProcAddress(hDll, (CHAR*)(pArrFunName->u1.Ordinal /*& 0x0ffff*/));
			}
			else {
				/* 找到该函数名称*/
				PIMAGE_IMPORT_BY_NAME pStcName = (PIMAGE_IMPORT_BY_NAME)
					((DWORD)hBase + pArrFunName->u1.Function);
				dwFunAddr = (DWORD)g_GetProcAddress(hDll, pStcName->Name);
			}
			/*确保可写*/
			DWORD dwOldProtect = 0;
			g_VirtualProtect(&pArrFunAddr[dwCount], 4, PAGE_READWRITE, &dwOldProtect);
			/*将函数地址放入IAT数组中对应成员内*/
			pArrFunAddr[dwCount].u1.AddressOfData = dwFunAddr;
			g_VirtualProtect(&pArrFunAddr[dwCount], 4, dwOldProtect, &dwOldProtect);
			/*下一个函数*/
			pArrFunName++;
			dwCount++;
		}
		/*下一个DLL*/
		pImp++;
	}
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_CREATE:
		CreateWindowEx(NULL,
			TEXT("Edit"),
			TEXT(""),
			WS_VISIBLE | WS_CHILD | WS_BORDER,
			10, 10, 120, 30,
			hWnd,
			(HMENU)521,
			(HINSTANCE)g_GetModuleHandleA,
			NULL);


		CreateWindowEx(NULL,
			TEXT("Button"),
			TEXT("KFC"),
			WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
			30, 80, 80, 30,
			hWnd,
			(HMENU)520,
			NULL,
			NULL);
		break;

	case WM_COMMAND:
		if (LOWORD(wParam) == 520 && HIWORD(wParam) == BN_CLICKED)
		{
			HWND hEdit = GetDlgItem(hWnd, 521);
			TCHAR szChar[9] = {};
			GetWindowText(hEdit, szChar, 9);
			if (wcscmp(szChar, L"kfc") == 0)
			{
				ShowWindow(hWnd, SW_HIDE);
				_asm {
					jmp emp1;
					_emit 0x09;
				emp1:
					call Uncompress;
					jmp emp2;
					_emit 0x09;
				emp2:
					call Decode;
					jmp emp3;
					_emit 0x09;
				emp3:
					call FixIAT;
					jmp g_PackInfo.TargetOep;
				}
			}
			else
			{
				ExitProcess(0);
			}
		}
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;

	case WM_CLOSE:
		ExitProcess(0);
		break;

	default:
		//默认处理方式  
		return DefWindowProc(hWnd, uMsg, wParam, lParam);
		break;
	}
	return  DefWindowProc(hWnd, uMsg, wParam, lParam);

}


int  Password()
{
	// 创建窗口的步骤:
	// 1. 注册窗口类
	//	 1.1 配置窗口类名
	//   1.2 配置窗口回调函数.
	//	 1.3 调用RegisterClass将窗口类注册到系统中
	// 2. 创建窗口
	// 3. 显示窗口(窗口创建出来之后,默认是隐藏的)
	// 4. 建立消息循环.

	WNDCLASS wndClass = { 0 };
	// 定义窗口类名(在创建窗口时会用到)
	wndClass.lpszClassName = (L"MyClass");

	// 定义窗口的回调函数(创建窗口时窗口类没有回调函数,会导致窗口 创建失败)
	wndClass.lpfnWndProc = WndProc;
	// 窗口背景画刷句柄
	wndClass.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);

	// 向系统注册一个窗口类
	RegisterClass(&wndClass);

	// 2. 使用已经注册过的窗口类来创建窗口
	HWND hWnd;
	hWnd = CreateWindowEx(
		NULL,
		(L"MyClass"), // 窗口类名
		(L"Please input password"), // 窗口标题
		WS_OVERLAPPEDWINDOW,// 窗口风格,由一系列的WS_XXXX
		550, 400, /*窗口的x,y坐标*/
		155, 155,/*窗口的宽和高*/
		NULL, /*父窗口句柄,如果没有父窗口,可以传NULL*/
		NULL, /*窗口的主菜单句柄,如果不需要可以传NULL*/
		NULL, /* 程序的实例句柄,来自WinMain函数的第一个参数*/
		NULL /* 附加参数, 传NULL*/
	);


	// 3. 显示窗口
	ShowWindow(hWnd, /* 要显示的窗口的句柄*/
		SW_SHOW /*显示的方式,是由一些列的SW_XXXX宏组成的,SW_HIDE*/
	);
	// 3.1 更新窗口
	UpdateWindow(hWnd);

	// 4. 建立消息循环
	MSG msg = { 0 };
	while (GetMessage(&msg, 0, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);

	}
	return msg.wParam;
}


