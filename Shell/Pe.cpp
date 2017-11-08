#include "stdafx.h"
#include "Pe.h"


CPe::CPe()
{
}


CPe::~CPe()
{
}

//��ȡԭOEP
DWORD CPe::GetOep()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pBuf);
	return pNt->OptionalHeader.AddressOfEntryPoint + 0x400000;
}

//��ȡĿ���ļ�
void CPe::ReadTargetFile(char* pPath)
{
	DWORD dwRealSize = 0;
	//1.���ļ�
	HANDLE hFile = CreateFileA(pPath, FILE_READ_ACCESS, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	//2.��ȡ�ļ���С
	m_dwFileSize = GetFileSize(hFile, NULL);
	//3.������ô��Ŀռ�
	m_pBuf = new CHAR[m_dwFileSize];
	memset(m_pBuf, 0, m_dwFileSize);
	//4.���ļ����ݶ�ȡ��������Ŀռ���
	ReadFile(hFile, m_pBuf, m_dwFileSize, &dwRealSize, 0);
	//5.�ر��ļ����
	CloseHandle(hFile);
}

//�������
void CPe::AddSection(PCHAR pName, PCHAR pSectionBuf, DWORD dwSectionSize, DWORD dwAttribute)
{
	//1.���ݸղŶ�ȡ��exe�ļ�������,�õ���������κ�,�µ�exe�ļ��Ĵ�С
	m_dwNewFileSize = m_dwFileSize + CalcAlignment(dwSectionSize, 0x200);
	//2.����ռ�
	m_pNewBuf = new CHAR[m_dwNewFileSize];
	memset(m_pNewBuf, 0, m_dwNewFileSize);
	//3.��ԭ����PE���ݿ�����������Ŀռ���
	memcpy(m_pNewBuf, m_pBuf, m_dwFileSize);
	delete[]m_pBuf;
	m_pBuf = m_pNewBuf;
	//4.�������ο�����PE�ļ��ĺ���
	memcpy(m_pNewBuf + m_dwFileSize, pSectionBuf, dwSectionSize);
	//5.�޸����α�
	m_pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	m_pNt = (PIMAGE_NT_HEADERS)(m_pDos->e_lfanew + m_pNewBuf);
	m_pSection = IMAGE_FIRST_SECTION(m_pNt);
	//�������һ����
	PIMAGE_SECTION_HEADER pLastSection = m_pSection + m_pNt->FileHeader.NumberOfSections - 1;
	//���������
	PIMAGE_SECTION_HEADER pNewSection = pLastSection + 1;
	//����
	pNewSection->Characteristics = dwAttribute;
	//������
	strcpy_s((char *)pNewSection->Name, 8, pName);
	//�ڴ��еĴ�С������Ҫ���룩
	pNewSection->Misc.VirtualSize = dwSectionSize;
	//���ڴ��е�λ��
	pNewSection->VirtualAddress = pLastSection->VirtualAddress +
		CalcAlignment(pLastSection->Misc.VirtualSize, 0x1000);
	//���ļ��еĴ�С(��Ҫ����)
	pNewSection->SizeOfRawData = CalcAlignment(dwSectionSize, 0x200);
	//���ļ��е�λ��
	pNewSection->PointerToRawData = pLastSection->PointerToRawData +
		pLastSection->SizeOfRawData;
	//6 �޸����������;����С
	m_pNt->FileHeader.NumberOfSections++;
	m_pNt->OptionalHeader.SizeOfImage = pNewSection->VirtualAddress + dwSectionSize;

}

//�����  ��ǰ��С,����Ĵ�С
DWORD CPe::CalcAlignment(DWORD dwSize, DWORD dwAlignment)
{
	if (dwSize%dwAlignment == 0)
	{
		return dwSize;
	}
	else
	{
		return(dwSize / dwAlignment + 1)*dwAlignment;
	}
}

//���ּӿǺ���ļ�
void CPe::SaveNewFile(char* pPath)
{
	DWORD dwRealSize = 0;
	//1.���ļ�
	HANDLE hFile = CreateFileA(pPath, FILE_WRITE_ACCESS, FILE_SHARE_READ,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	//2.���ڴ��е�����д�뵽�ļ���
	WriteFile(hFile, m_pNewBuf, m_dwNewFileSize, &dwRealSize, NULL);
	//3.�ر��ļ����
	CloseHandle(hFile);
}

//�޸��ض�λ
void CPe::FixRloc(PCHAR pBuf)
{
	//��������Ժ��Dosͷ
	PIMAGE_DOS_HEADER pDosNew = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNtNew = (PIMAGE_NT_HEADERS)(pDosNew->e_lfanew + m_pBuf);
	//eason��
	PIMAGE_SECTION_HEADER pNewSec = IMAGE_FIRST_SECTION(pNtNew) + pNtNew->FileHeader.NumberOfSections - 1;

	//eason����ʼλ��
	PCHAR pFunbegin = m_pBuf + pNewSec->PointerToRawData;
	PIMAGE_DOS_HEADER pDosStub = (PIMAGE_DOS_HEADER)(pFunbegin);
	PIMAGE_NT_HEADERS pNtStub = (PIMAGE_NT_HEADERS)(pDosStub->e_lfanew + pFunbegin);
	PIMAGE_DATA_DIRECTORY pRelocDirStub = (pNtStub->OptionalHeader.DataDirectory + 5);

	//�ض�λ���ݽṹ��
	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(pRelocDirStub->VirtualAddress + pFunbegin);
	while (pReloc->SizeOfBlock != 0)
	{
		DWORD dwCount = (pReloc->SizeOfBlock - 8) / 2;
		//�����е�λ��
		PTYPE pType = (PTYPE)(pReloc + 1);
		for (size_t i = 0; i < dwCount; ++i)
		{
			if (pType->type == 3)
			{
				//��Ҫ�ض�λ���ݵ�ַ
				PDWORD pReloction = (PDWORD)(pReloc->VirtualAddress + pType->offset + pFunbegin);
				//text���ڵĲ�ֵ 402108 - 400000
				DWORD Chazhi = *pReloction - (DWORD)pBuf;
				//�޸��ض�λ
				*pReloction = Chazhi + GetNewSectionRVA() + 0x400000;
			}
			pType++;
		}
		/*// 2. �޸�ÿ����Ļ�ֵpRelocInfoStub->VirtualAddress
		// 0x1000��Ҫ����ΪdwFirstRVA
		// 0x2000 ����ΪdwFirstRVA + 0x1000
		// 0xxxxx ����ΪdwFirstRVA - 0x1000 + 0xxxxx
		if (pReloc->VirtualAddress < dwStubSecIdata) {
		pReloc->VirtualAddress = GetNewSectionRVA() - dwStubSecCode + pReloc->VirtualAddress;
		}
		else {
		pReloc->VirtualAddress = GetNewSectionRVA() - dwStubSecIdata + pReloc->VirtualAddress;
		}*/
		pReloc = (PIMAGE_BASE_RELOCATION)((PCHAR)pReloc + pReloc->SizeOfBlock);
	}

}


//��ȡ������RVA
DWORD CPe::GetNewSectionRVA()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_SECTION_HEADER pLastSection = pSection + pNt->FileHeader.NumberOfSections - 1;

	return pLastSection->VirtualAddress;
}

//��ȡ������RVA
DWORD CPe::GetNewSectionRva()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_SECTION_HEADER pLastSection = pSection + pNt->FileHeader.NumberOfSections - 1;
	return pLastSection->VirtualAddress + CalcAlignment(pLastSection->Misc.VirtualSize, 0x1000);

}

//����
void CPe::Encrypt()
{
	PIMAGE_SECTION_HEADER pSecond=m_pSection;
	for (int i = 0; i <= m_pNt->FileHeader.NumberOfSections; i++)
	{
		if (strcmp(".text", (char*)m_pSection[i].Name) == 0)
		{
			pSecond = m_pSection + i;
			break;
		}
	}
	for (int i = 0; i < pSecond->SizeOfRawData; i++)
	{
		PCHAR pStart = pSecond->PointerToRawData + m_pNewBuf;
		pStart[i] ^= 0x15;
	}
	pSecond->Characteristics = 0xE0000020;
}

//ȥ�������ַ
void CPe::CancleRandomBase()
{
	m_pNt->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
}

//������OEP
void CPe::SetNewOep(DWORD dwNewOep)
{
	m_pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	m_pNt = (PIMAGE_NT_HEADERS)(m_pDos->e_lfanew + m_pNewBuf);
	m_pNt->OptionalHeader.AddressOfEntryPoint = dwNewOep;
}

//��ѹ��
void CPe::Compress(PPACKINFO pPackInfo1)
{
	PIMAGE_SECTION_HEADER pSecond = m_pSection;
	PCHAR pText = pSecond->PointerToRawData + m_pBuf;
	// ѹ�����ֽ���,����ѹ�����������ռ�
	uLong UnCompressSize = pSecond->SizeOfRawData;
	byte* buf = NULL;
	// ����ʵ��ѹ��tlen���ȵ��ֽ���Ҫ���ڴ��С
	uLong CompressSize = compressBound(UnCompressSize);
	// �����ڴ棬���ڴ��ѹ������ֽ�
	if ((buf = (byte*)malloc(sizeof(byte) * CompressSize)) == NULL) {
		printf("����ռ�ʧ��!\n");
		return;
	}

	// ѹ��
	// buf			���ѹ������ֽڵĻ�������ַ
	// CompressSize	ѹ������ֽڳ���
	// pText		Ҫѹ���Ļ�����
	// UnCompressSizeҪѹ���Ļ������ֽ���
	if (compress(buf, &CompressSize, (byte*)pText, UnCompressSize) != Z_OK)
	{
		printf("ѹ��ʧ��!\n");
		return;
	}
	printf("ѹ���ɹ�!\n");
	//��հ�,��ߵ�����ǰ��
	memcpy(pText, buf, CompressSize);
	pSecond->SizeOfRawData = CalcAlignment(CompressSize, 0x200);
	DWORD dwChazhi = UnCompressSize - pSecond->SizeOfRawData;
	for (int i = 0; i < m_pNt->FileHeader.NumberOfSections; ++i)
	{
		//ѹ����Ķλ�ַ
		PVOID address = (PVOID)((pSecond + i)->PointerToRawData +
			CalcAlignment((pSecond + i)->SizeOfRawData, 0x200) + m_pNewBuf);

		memcpy(address, (pSecond + i + 1)->PointerToRawData + m_pNewBuf, (pSecond + i + 1)->SizeOfRawData);

		(pSecond + i + 1)->PointerToRawData = (pSecond + i + 1)->PointerToRawData - dwChazhi;
	}
	printf("ѹ���ɹ�!\n");
	if (buf != nullptr)
	{
		free(buf);
		buf = nullptr;
	}
	m_dwNewFileSize -= dwChazhi;

	//����Stubѹ����С
	PIMAGE_DOS_HEADER pDosStubSec = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNtStubSec = (PIMAGE_NT_HEADERS)(m_pBuf + pDosStubSec->e_lfanew);
	PIMAGE_SECTION_HEADER pSecStubSec = IMAGE_FIRST_SECTION(pNtStubSec) + pNtStubSec->FileHeader.NumberOfSections - 1;
	PPACKINFO pPackInfo = (PPACKINFO)(m_pBuf + pSecStubSec->PointerToRawData + m_dwPackInfoOffset);
	pPackInfo->CompressSize = CompressSize;
	pPackInfo->UnCompressSize = UnCompressSize;
}

void  CPe::FixINT(PCHAR pBuf)
{
	//�ҵ������ε���ʼλ��
	PIMAGE_DOS_HEADER pDosNew = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNtNew = (PIMAGE_NT_HEADERS)(pDosNew->e_lfanew + m_pBuf);
	//eason��
	PIMAGE_SECTION_HEADER pNewSec = IMAGE_FIRST_SECTION(pNtNew) + pNtNew->FileHeader.NumberOfSections - 1;

	DWORD dwNewSectionRVA = pNewSec->VirtualAddress;
	DWORD dwFOA = pNewSec->PointerToRawData;
	//stub
	PIMAGE_DOS_HEADER pStubDos = (PIMAGE_DOS_HEADER)(m_pBuf + dwFOA);
	PIMAGE_NT_HEADERS pStubNt = (PIMAGE_NT_HEADERS)(pStubDos->e_lfanew + m_pBuf + dwFOA);
	PIMAGE_DATA_DIRECTORY pStubDir = (pStubNt->OptionalHeader.DataDirectory + 1);
	PIMAGE_IMPORT_DESCRIPTOR pStubImprotDir = (PIMAGE_IMPORT_DESCRIPTOR)(pStubDir->VirtualAddress + m_pBuf + dwFOA);
	while (pStubImprotDir->Name)
	{
		pStubImprotDir->FirstThunk += dwNewSectionRVA;
		pStubImprotDir->Name += dwNewSectionRVA;
		PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)(pStubImprotDir->OriginalFirstThunk + m_pBuf + dwFOA);
		pStubImprotDir->OriginalFirstThunk += dwNewSectionRVA;
		while (pINT->u1.Ordinal)
		{
			pINT->u1.Ordinal += dwNewSectionRVA;
			pINT++;
		}
		//ѭ������ģ��
		pStubImprotDir++;
	}
	//exe
	PIMAGE_DOS_HEADER pExeDos = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pExeNt = (PIMAGE_NT_HEADERS)(pExeDos->e_lfanew + m_pBuf);
	PIMAGE_DATA_DIRECTORY  pExeDri = (pExeNt->OptionalHeader.DataDirectory + 1);

	//����ɵ�INT
	PPACKINFO pPack = (PPACKINFO)(m_pBuf + dwFOA + m_dwPackInfoOffset);
	pPack->dwOldINTRva = pExeDri->VirtualAddress;

	//new INT
	pExeDri->Size = pStubDir->Size;
	pExeDri->VirtualAddress = pStubDir->VirtualAddress + dwNewSectionRVA;

	PIMAGE_DATA_DIRECTORY pStubIAT = (pStubNt->OptionalHeader.DataDirectory + 12);
	PIMAGE_DATA_DIRECTORY  pExeIAT = (pExeNt->OptionalHeader.DataDirectory + 12);
	pExeIAT->Size = pStubIAT->Size;
	pExeIAT->VirtualAddress = pStubIAT->VirtualAddress + dwNewSectionRVA;
}

