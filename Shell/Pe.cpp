#include "stdafx.h"
#include "Pe.h"


CPe::CPe()
{
}


CPe::~CPe()
{
}

//获取原OEP
DWORD CPe::GetOep()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pBuf);
	return pNt->OptionalHeader.AddressOfEntryPoint + 0x400000;
}

//读取目标文件
void CPe::ReadTargetFile(char* pPath)
{
	DWORD dwRealSize = 0;
	//1.打开文件
	HANDLE hFile = CreateFileA(pPath, FILE_READ_ACCESS, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	//2.获取文件大小
	m_dwFileSize = GetFileSize(hFile, NULL);
	//3.申请这么大的空间
	m_pBuf = new CHAR[m_dwFileSize];
	memset(m_pBuf, 0, m_dwFileSize);
	//4.把文件内容读取到申请出的空间中
	ReadFile(hFile, m_pBuf, m_dwFileSize, &dwRealSize, 0);
	//5.关闭文件句柄
	CloseHandle(hFile);
}

//添加区段
void CPe::AddSection(PCHAR pName, PCHAR pSectionBuf, DWORD dwSectionSize, DWORD dwAttribute)
{
	//1.根据刚才读取的exe文件的内容,得到添加完区段后,新的exe文件的大小
	m_dwNewFileSize = m_dwFileSize + CalcAlignment(dwSectionSize, 0x200);
	//2.申请空间
	m_pNewBuf = new CHAR[m_dwNewFileSize];
	memset(m_pNewBuf, 0, m_dwNewFileSize);
	//3.把原来的PE内容拷贝到新申请的空间中
	memcpy(m_pNewBuf, m_pBuf, m_dwFileSize);
	delete[]m_pBuf;
	m_pBuf = m_pNewBuf;
	//4.把新区段拷贝到PE文件的后面
	memcpy(m_pNewBuf + m_dwFileSize, pSectionBuf, dwSectionSize);
	//5.修改区段表
	m_pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	m_pNt = (PIMAGE_NT_HEADERS)(m_pDos->e_lfanew + m_pNewBuf);
	m_pSection = IMAGE_FIRST_SECTION(m_pNt);
	//区段最后一个段
	PIMAGE_SECTION_HEADER pLastSection = m_pSection + m_pNt->FileHeader.NumberOfSections - 1;
	//添加新区段
	PIMAGE_SECTION_HEADER pNewSection = pLastSection + 1;
	//属性
	pNewSection->Characteristics = dwAttribute;
	//区段名
	strcpy_s((char *)pNewSection->Name, 8, pName);
	//内存中的大小（不需要对齐）
	pNewSection->Misc.VirtualSize = dwSectionSize;
	//在内存中的位置
	pNewSection->VirtualAddress = pLastSection->VirtualAddress +
		CalcAlignment(pLastSection->Misc.VirtualSize, 0x1000);
	//在文件中的大小(需要对齐)
	pNewSection->SizeOfRawData = CalcAlignment(dwSectionSize, 0x200);
	//在文件中的位置
	pNewSection->PointerToRawData = pLastSection->PointerToRawData +
		pLastSection->SizeOfRawData;
	//6 修改区段数量和镜像大小
	m_pNt->FileHeader.NumberOfSections++;
	m_pNt->OptionalHeader.SizeOfImage = pNewSection->VirtualAddress + dwSectionSize;

}

//对齐块  当前大小,对齐的大小
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

//保持加壳后的文件
void CPe::SaveNewFile(char* pPath)
{
	DWORD dwRealSize = 0;
	//1.打开文件
	HANDLE hFile = CreateFileA(pPath, FILE_WRITE_ACCESS, FILE_SHARE_READ,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	//2.把内存中的数据写入到文件中
	WriteFile(hFile, m_pNewBuf, m_dwNewFileSize, &dwRealSize, NULL);
	//3.关闭文件句柄
	CloseHandle(hFile);
}

//修复重定位
void CPe::FixRloc(PCHAR pBuf)
{
	//添加区段以后的Dos头
	PIMAGE_DOS_HEADER pDosNew = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNtNew = (PIMAGE_NT_HEADERS)(pDosNew->e_lfanew + m_pBuf);
	//eason段
	PIMAGE_SECTION_HEADER pNewSec = IMAGE_FIRST_SECTION(pNtNew) + pNtNew->FileHeader.NumberOfSections - 1;

	//eason段起始位置
	PCHAR pFunbegin = m_pBuf + pNewSec->PointerToRawData;
	PIMAGE_DOS_HEADER pDosStub = (PIMAGE_DOS_HEADER)(pFunbegin);
	PIMAGE_NT_HEADERS pNtStub = (PIMAGE_NT_HEADERS)(pDosStub->e_lfanew + pFunbegin);
	PIMAGE_DATA_DIRECTORY pRelocDirStub = (pNtStub->OptionalHeader.DataDirectory + 5);

	//重定位数据结构体
	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(pRelocDirStub->VirtualAddress + pFunbegin);
	while (pReloc->SizeOfBlock != 0)
	{
		DWORD dwCount = (pReloc->SizeOfBlock - 8) / 2;
		//数组中的位置
		PTYPE pType = (PTYPE)(pReloc + 1);
		for (size_t i = 0; i < dwCount; ++i)
		{
			if (pType->type == 3)
			{
				//需要重定位数据地址
				PDWORD pReloction = (PDWORD)(pReloc->VirtualAddress + pType->offset + pFunbegin);
				//text段内的差值 402108 - 400000
				DWORD Chazhi = *pReloction - (DWORD)pBuf;
				//修复重定位
				*pReloction = Chazhi + GetNewSectionRVA() + 0x400000;
			}
			pType++;
		}
		/*// 2. 修复每个块的基值pRelocInfoStub->VirtualAddress
		// 0x1000需要修正为dwFirstRVA
		// 0x2000 修正为dwFirstRVA + 0x1000
		// 0xxxxx 修正为dwFirstRVA - 0x1000 + 0xxxxx
		if (pReloc->VirtualAddress < dwStubSecIdata) {
		pReloc->VirtualAddress = GetNewSectionRVA() - dwStubSecCode + pReloc->VirtualAddress;
		}
		else {
		pReloc->VirtualAddress = GetNewSectionRVA() - dwStubSecIdata + pReloc->VirtualAddress;
		}*/
		pReloc = (PIMAGE_BASE_RELOCATION)((PCHAR)pReloc + pReloc->SizeOfBlock);
	}

}


//获取新区段RVA
DWORD CPe::GetNewSectionRVA()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_SECTION_HEADER pLastSection = pSection + pNt->FileHeader.NumberOfSections - 1;

	return pLastSection->VirtualAddress;
}

//获取新区段RVA
DWORD CPe::GetNewSectionRva()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_SECTION_HEADER pLastSection = pSection + pNt->FileHeader.NumberOfSections - 1;
	return pLastSection->VirtualAddress + CalcAlignment(pLastSection->Misc.VirtualSize, 0x1000);

}

//加密
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

//去除随机基址
void CPe::CancleRandomBase()
{
	m_pNt->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
}

//设置新OEP
void CPe::SetNewOep(DWORD dwNewOep)
{
	m_pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	m_pNt = (PIMAGE_NT_HEADERS)(m_pDos->e_lfanew + m_pNewBuf);
	m_pNt->OptionalHeader.AddressOfEntryPoint = dwNewOep;
}

//加压缩
void CPe::Compress(PPACKINFO pPackInfo1)
{
	PIMAGE_SECTION_HEADER pSecond = m_pSection;
	PCHAR pText = pSecond->PointerToRawData + m_pBuf;
	// 压缩的字节数,用于压缩库计算申请空间
	uLong UnCompressSize = pSecond->SizeOfRawData;
	byte* buf = NULL;
	// 计算实际压缩tlen长度的字节需要的内存大小
	uLong CompressSize = compressBound(UnCompressSize);
	// 申请内存，用于存放压缩后的字节
	if ((buf = (byte*)malloc(sizeof(byte) * CompressSize)) == NULL) {
		printf("分配空间失败!\n");
		return;
	}

	// 压缩
	// buf			存放压缩后的字节的缓冲区地址
	// CompressSize	压缩后的字节长度
	// pText		要压缩的缓冲区
	// UnCompressSize要压缩的缓冲区字节数
	if (compress(buf, &CompressSize, (byte*)pText, UnCompressSize) != Z_OK)
	{
		printf("压缩失败!\n");
		return;
	}
	printf("压缩成功!\n");
	//填补空白,后边的区段前移
	memcpy(pText, buf, CompressSize);
	pSecond->SizeOfRawData = CalcAlignment(CompressSize, 0x200);
	DWORD dwChazhi = UnCompressSize - pSecond->SizeOfRawData;
	for (int i = 0; i < m_pNt->FileHeader.NumberOfSections; ++i)
	{
		//压缩后的段基址
		PVOID address = (PVOID)((pSecond + i)->PointerToRawData +
			CalcAlignment((pSecond + i)->SizeOfRawData, 0x200) + m_pNewBuf);

		memcpy(address, (pSecond + i + 1)->PointerToRawData + m_pNewBuf, (pSecond + i + 1)->SizeOfRawData);

		(pSecond + i + 1)->PointerToRawData = (pSecond + i + 1)->PointerToRawData - dwChazhi;
	}
	printf("压缩成功!\n");
	if (buf != nullptr)
	{
		free(buf);
		buf = nullptr;
	}
	m_dwNewFileSize -= dwChazhi;

	//告诉Stub压缩大小
	PIMAGE_DOS_HEADER pDosStubSec = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNtStubSec = (PIMAGE_NT_HEADERS)(m_pBuf + pDosStubSec->e_lfanew);
	PIMAGE_SECTION_HEADER pSecStubSec = IMAGE_FIRST_SECTION(pNtStubSec) + pNtStubSec->FileHeader.NumberOfSections - 1;
	PPACKINFO pPackInfo = (PPACKINFO)(m_pBuf + pSecStubSec->PointerToRawData + m_dwPackInfoOffset);
	pPackInfo->CompressSize = CompressSize;
	pPackInfo->UnCompressSize = UnCompressSize;
}

void  CPe::FixINT(PCHAR pBuf)
{
	//找到新区段的起始位置
	PIMAGE_DOS_HEADER pDosNew = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNtNew = (PIMAGE_NT_HEADERS)(pDosNew->e_lfanew + m_pBuf);
	//eason段
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
		//循环遍历模块
		pStubImprotDir++;
	}
	//exe
	PIMAGE_DOS_HEADER pExeDos = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pExeNt = (PIMAGE_NT_HEADERS)(pExeDos->e_lfanew + m_pBuf);
	PIMAGE_DATA_DIRECTORY  pExeDri = (pExeNt->OptionalHeader.DataDirectory + 1);

	//保存旧的INT
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

