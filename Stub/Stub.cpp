// Stub.cpp : ���� DLL Ӧ�ó���ĵ���������
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
		PUSH 402148					// ����δ��������������Ĳ�������������      
		MOV EAX, DWORD PTR FS : [0]
		PUSH EAX
		MOV DWORD PTR FS : [0], ESP
		ADD ESP, 6
		PUSH EBX
		PUSH ESI
		PUSH EDI
		ADD BYTE PTR DS : [EAX], AL // ����ָ����Բ�Ҫ
		jmp hua
		hua :
		call Init;
		jmp emp1;
		_emit 0x09;
	emp1:
		mov eax, dword ptr fs : [0x30]//����Ƿ񱻵���
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
		mov eax, fs:[0x30];		//�ҵ�PEB
		mov eax, [eax + 0x0C];	//�ҵ���LDR
		mov eax, [eax + 0x0C];	//�ҵ��˵�һ���ڵ�
		mov eax, [eax];			//�ҵ���ntdll
		mov eax, [eax];			//�ҵ���kernel32.dll
		mov ebx, dword ptr ds : [eax + 0x18];
		mov pBuf, ebx;
	}
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
	//����Ŀ¼��
	PIMAGE_DATA_DIRECTORY pExportDir =
		(pNt->OptionalHeader.DataDirectory + 0);
	//������
	PIMAGE_EXPORT_DIRECTORY pExport =
		(PIMAGE_EXPORT_DIRECTORY)(pExportDir->VirtualAddress + pBuf);
	//1  �ҵ����������ƣ���ַ�����
	//��ַ��
	PDWORD pExpAddr = (PDWORD)(pExport->AddressOfFunctions + pBuf);
	//���Ʊ�
	PDWORD pExpName = (PDWORD)(pExport->AddressOfNames + pBuf);
	//��ű�
	PWORD pExpOrd = (PWORD)(pExport->AddressOfNameOrdinals + pBuf);
	PVOID pGetProcAddress = 0;
	PVOID pLoadLibry = 0;
	//2  �����Ʊ���ȥ����GetProcAddress����ַ���
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

//��ڵ�
void Init()
{
	MyGetProcAddress((LPVOID*)&g_GetProcAddress, (LPVOID*)&g_LoadLibraryA);
	g_GetModuleHandleA = (MYGETMODULEHANDLEA)g_GetProcAddress(g_LoadLibraryA("kernel32.dll"), "GetModuleHandleA");
	g_VirtualAlloc = (MYVIRTUALALLOC)g_GetProcAddress(g_GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
	g_VirtualFree = (MYVIRTUALFREE)g_GetProcAddress(g_GetModuleHandleA("kernel32.dll"), "VirtualFree");
	g_VirtualProtect = (MYVIRTUALPROTECT)g_GetProcAddress(g_GetModuleHandleA("kernel32.dll"), "VirtualProtect");
}

//����
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
	//�ж��Ƿ��ѹ��
	if (!g_PackInfo.CompressSize || !g_PackInfo.UnCompressSize)
	{
		return;
	}

	PCHAR pBuf = (PCHAR)g_GetModuleHandleA(NULL);
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	//����ε�ַ
	PCHAR pStart = pSection->VirtualAddress + pBuf;
	//����ռ��Ž�ѹ��Ĵ���
	PBYTE pUnCompressSize = (PBYTE)g_VirtualAlloc(NULL, g_PackInfo.UnCompressSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pUnCompressSize == NULL) return;

	//�ı����ζ�д���ԣ���֤�ɶ�д
	DWORD dwOldProt = 0;
	g_VirtualProtect(pStart, 0x4e00, PAGE_EXECUTE_READWRITE, &dwOldProt);

	//��ѹ��
	// pUnCompressSize  ��Ž�ѹ����Ļ�������ַ
	// nUnComLen		��ѹ����ֽ���
	// pStart			Ҫ��ѹ�Ļ�������ַ
	// g_PackInfo.CompressSize	Ҫ��ѹ�ĳ���
	if (uncompress((PBYTE)pUnCompressSize, &g_PackInfo.UnCompressSize, (PBYTE)pStart, g_PackInfo.CompressSize) != Z_OK) {
		//��ѹʧ��,�ͷſռ�*
		g_VirtualFree(pUnCompressSize, 0, MEM_RELEASE);
		return;
	}
	//��ѹ�ɹ�
	memcpy(pStart, pUnCompressSize, g_PackInfo.UnCompressSize);
	//�޸���������
	g_VirtualProtect(pStart, 0x4e00, PAGE_EXECUTE_READWRITE, &dwOldProt);
	//����δ�С���Ļ���
	//��֤��д
	g_VirtualProtect(pSection, 16, PAGE_READWRITE, &dwOldProt);
	//�޸����δ�С
	pSection->SizeOfRawData = g_PackInfo.UnCompressSize;
	g_VirtualProtect(pSection, 16, dwOldProt, &dwOldProt);
}

//�޸��ض�λ
void FixSrcReloc()
{
	// �ҵ�ԭ�ض�λ����Ϣ�ĵ�ַ
	HMODULE hBase = g_GetModuleHandleA(0);
	//Ĭ�ϼ��ػ�ַ
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)hBase + pDos->e_lfanew);
	// ��ȥĬ�ϼ��ػ�ַ
	DWORD dwImageBase = 0x400000;
	//�Ƿ����ض�λ��Ϣ
	if (!g_PackInfo.dwOldRelocRva || !g_PackInfo.dwOldRelocSize) {
		return;
	}
	//�ҵ�Ҫ�ض�λ������
	PIMAGE_BASE_RELOCATION  pRelocAddr = (PIMAGE_BASE_RELOCATION)((DWORD)hBase + g_PackInfo.dwOldRelocRva);
	DWORD dwCount = 0;
	while (pRelocAddr->VirtualAddress && dwCount < g_PackInfo.dwOldRelocSize) {
		// �ض�λ���������ʼ��ַ
		PRELOCTYPE pOffSetArr = (PRELOCTYPE)(pRelocAddr + 1);
		// �����Ա����
		DWORD dwCount = (pRelocAddr->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOCTYPE);
		for (DWORD i = 0; i < dwCount; ++i) {
			if (pOffSetArr[i].type == 3) {
				//Ҫ�ض�λ�����ݵ�RVA
				DWORD dwOffset = pOffSetArr[i].offset + pRelocAddr->VirtualAddress;
				//Ҫ�ض�λ�����ݵ�VA
				PDWORD pAddr = (PDWORD)((DWORD)hBase + dwOffset);
				//��֤��д
				DWORD dwOldProtect = 0;
				if (!g_VirtualProtect(pAddr, 4, PAGE_READWRITE, &dwOldProtect)) return;
				/*�޸���ֵ
				�޸����ֵ = �޸�ǰ��ֵ - dwImageBase + hBase*/
				*pAddr = *pAddr - dwImageBase + (DWORD)hBase;
				if (!g_VirtualProtect(pAddr, 4, dwOldProtect, &dwOldProtect)) return;

			}
		}
		// ���ض�λ���ݴ�С
		dwCount += pRelocAddr->SizeOfBlock;
		// ��λ����һ������
		pRelocAddr = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocAddr + pRelocAddr->SizeOfBlock);
	}
}

void FixIAT() {
	/* ��ȡINT�ĵ�ַ */
	DWORD dwRva = g_PackInfo.dwOldINTRva;
	HMODULE hBase = g_GetModuleHandleA(0);
	PIMAGE_IMPORT_DESCRIPTOR pImp = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hBase + dwRva);
	/*�޸������*/
	while (pImp->Name) {
		/*����DLL*/
		PCHAR pDllName = (PCHAR)((DWORD)hBase + pImp->Name);
		HMODULE hDll = g_LoadLibraryA(pDllName);
		/*��ȡ����������ʼ��ַ�͵�ַ������ʼ��ַ*/
		PIMAGE_THUNK_DATA pArrFunName = (PIMAGE_THUNK_DATA)((DWORD)hBase + pImp->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pArrFunAddr = (PIMAGE_THUNK_DATA)((DWORD)hBase + pImp->FirstThunk);
		/*��������/��Ż�ȡ������ַ�������Ӧ�ĵ�ַ������*/
		DWORD dwCount = 0;
		while (pArrFunName->u1.Ordinal) {
			/*�ñ������ڴ���ҵ��ĺ�����ַ*/
			DWORD dwFunAddr = 0;
			if (IMAGE_SNAP_BY_ORDINAL(pArrFunName->u1.Ordinal)) {
				dwFunAddr = (DWORD)g_GetProcAddress(hDll, (CHAR*)(pArrFunName->u1.Ordinal /*& 0x0ffff*/));
			}
			else {
				/* �ҵ��ú�������*/
				PIMAGE_IMPORT_BY_NAME pStcName = (PIMAGE_IMPORT_BY_NAME)
					((DWORD)hBase + pArrFunName->u1.Function);
				dwFunAddr = (DWORD)g_GetProcAddress(hDll, pStcName->Name);
			}
			/*ȷ����д*/
			DWORD dwOldProtect = 0;
			g_VirtualProtect(&pArrFunAddr[dwCount], 4, PAGE_READWRITE, &dwOldProtect);
			/*��������ַ����IAT�����ж�Ӧ��Ա��*/
			pArrFunAddr[dwCount].u1.AddressOfData = dwFunAddr;
			g_VirtualProtect(&pArrFunAddr[dwCount], 4, dwOldProtect, &dwOldProtect);
			/*��һ������*/
			pArrFunName++;
			dwCount++;
		}
		/*��һ��DLL*/
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
		//Ĭ�ϴ���ʽ  
		return DefWindowProc(hWnd, uMsg, wParam, lParam);
		break;
	}
	return  DefWindowProc(hWnd, uMsg, wParam, lParam);

}


int  Password()
{
	// �������ڵĲ���:
	// 1. ע�ᴰ����
	//	 1.1 ���ô�������
	//   1.2 ���ô��ڻص�����.
	//	 1.3 ����RegisterClass��������ע�ᵽϵͳ��
	// 2. ��������
	// 3. ��ʾ����(���ڴ�������֮��,Ĭ�������ص�)
	// 4. ������Ϣѭ��.

	WNDCLASS wndClass = { 0 };
	// ���崰������(�ڴ�������ʱ���õ�)
	wndClass.lpszClassName = (L"MyClass");

	// ���崰�ڵĻص�����(��������ʱ������û�лص�����,�ᵼ�´��� ����ʧ��)
	wndClass.lpfnWndProc = WndProc;
	// ���ڱ�����ˢ���
	wndClass.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);

	// ��ϵͳע��һ��������
	RegisterClass(&wndClass);

	// 2. ʹ���Ѿ�ע����Ĵ���������������
	HWND hWnd;
	hWnd = CreateWindowEx(
		NULL,
		(L"MyClass"), // ��������
		(L"Please input password"), // ���ڱ���
		WS_OVERLAPPEDWINDOW,// ���ڷ��,��һϵ�е�WS_XXXX
		550, 400, /*���ڵ�x,y����*/
		155, 155,/*���ڵĿ�͸�*/
		NULL, /*�����ھ��,���û�и�����,���Դ�NULL*/
		NULL, /*���ڵ����˵����,�������Ҫ���Դ�NULL*/
		NULL, /* �����ʵ�����,����WinMain�����ĵ�һ������*/
		NULL /* ���Ӳ���, ��NULL*/
	);


	// 3. ��ʾ����
	ShowWindow(hWnd, /* Ҫ��ʾ�Ĵ��ڵľ��*/
		SW_SHOW /*��ʾ�ķ�ʽ,����һЩ�е�SW_XXXX����ɵ�,SW_HIDE*/
	);
	// 3.1 ���´���
	UpdateWindow(hWnd);

	// 4. ������Ϣѭ��
	MSG msg = { 0 };
	while (GetMessage(&msg, 0, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);

	}
	return msg.wParam;
}


