// Shell.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "Pe.h"
#define  PATH "C:\\Users\\LMT\\Documents\\Tencent Files\\504263852\\FileRecv\\PETest.exe"

void Pack(char* pPath)
{
	CPe obj;
	obj.ReadTargetFile(pPath);
	//1.把stub载入到内存
	HMODULE hStub = LoadLibrary(L"C:\\Users\\LMT\\Documents\\Tencent Files\\504263852\\FileRecv\\Shell\\Release\\Stub.dll");
	PCHAR pStubBuf = (PCHAR)hStub;
	//2.在内存中找到 g_PackInfo
	PPACKINFO pPackInfo = (PPACKINFO)GetProcAddress(hStub, "g_PackInfo");
	//保存pPackInfo的偏移值,设置INT表时用
	obj.m_dwPackInfoOffset = (DWORD)pPackInfo - (DWORD)hStub;
	//3.找到了之后,设置好跳转的OEP
	pPackInfo->TargetOep = (void*)obj.GetOep();

	//4.把sutb部分的代码段添加为目标程序的新区段
	PIMAGE_DOS_HEADER pStubDos = (PIMAGE_DOS_HEADER)pStubBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pStubDos->e_lfanew + pStubBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	//添加保存DLL代码的区段
	obj.AddSection(".eason", pStubBuf,
		pNt->OptionalHeader.SizeOfImage, pSection->Characteristics);

	//5.修复dll重定位
	//原区段RVA
	DWORD dwStartRva = (DWORD)pPackInfo->StartAddreass - (DWORD)pStubBuf;
	obj.FixRloc(pStubBuf);
	//修复dllINT
	obj.FixINT(pStubBuf);

	//6.把目标程序的OEP设置为stub中的start函数
	//段内偏移
	DWORD NewSectionRVA = obj.GetNewSectionRVA();
	DWORD dwNewOEP = (dwStartRva + NewSectionRVA);
	obj.SetNewOep(dwNewOEP);
	//去除随机基址 
	obj.CancleRandomBase();
	//加密
	obj.Encrypt();
	//压缩
	obj.Compress(pPackInfo);
	//7.保存成文件
	obj.SaveNewFile("C:\\Users\\lmt\\Documents\\Tencent Files\\504263852\\FileRecv\\Test_shell.exe");
}

int main()
{
	Pack(PATH);
	return 0;
}



