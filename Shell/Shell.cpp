// Shell.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "Pe.h"
#define  PATH "C:\\Users\\LMT\\Documents\\Tencent Files\\504263852\\FileRecv\\PETest.exe"

void Pack(char* pPath)
{
	CPe obj;
	obj.ReadTargetFile(pPath);
	//1.��stub���뵽�ڴ�
	HMODULE hStub = LoadLibrary(L"C:\\Users\\LMT\\Documents\\Tencent Files\\504263852\\FileRecv\\Shell\\Release\\Stub.dll");
	PCHAR pStubBuf = (PCHAR)hStub;
	//2.���ڴ����ҵ� g_PackInfo
	PPACKINFO pPackInfo = (PPACKINFO)GetProcAddress(hStub, "g_PackInfo");
	//����pPackInfo��ƫ��ֵ,����INT��ʱ��
	obj.m_dwPackInfoOffset = (DWORD)pPackInfo - (DWORD)hStub;
	//3.�ҵ���֮��,���ú���ת��OEP
	pPackInfo->TargetOep = (void*)obj.GetOep();

	//4.��sutb���ֵĴ�������ΪĿ������������
	PIMAGE_DOS_HEADER pStubDos = (PIMAGE_DOS_HEADER)pStubBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pStubDos->e_lfanew + pStubBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	//��ӱ���DLL���������
	obj.AddSection(".eason", pStubBuf,
		pNt->OptionalHeader.SizeOfImage, pSection->Characteristics);

	//5.�޸�dll�ض�λ
	//ԭ����RVA
	DWORD dwStartRva = (DWORD)pPackInfo->StartAddreass - (DWORD)pStubBuf;
	obj.FixRloc(pStubBuf);
	//�޸�dllINT
	obj.FixINT(pStubBuf);

	//6.��Ŀ������OEP����Ϊstub�е�start����
	//����ƫ��
	DWORD NewSectionRVA = obj.GetNewSectionRVA();
	DWORD dwNewOEP = (dwStartRva + NewSectionRVA);
	obj.SetNewOep(dwNewOEP);
	//ȥ�������ַ 
	obj.CancleRandomBase();
	//����
	obj.Encrypt();
	//ѹ��
	obj.Compress(pPackInfo);
	//7.������ļ�
	obj.SaveNewFile("C:\\Users\\lmt\\Documents\\Tencent Files\\504263852\\FileRecv\\Test_shell.exe");
}

int main()
{
	Pack(PATH);
	return 0;
}



