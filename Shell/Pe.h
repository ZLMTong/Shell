#pragma once

#include<windows.h>
#include "..\Stub\stub.h"
// ʹ�ø�ѹ���������Ҫ����3������Ԥ����ָ��
#define ZLIB_WINAPI
#include "zlib/zlib.h"
#pragma comment(lib,"zlib/zlibstat.lib")


class CPe
{
public:
	typedef struct _TYPE
	{
		unsigned short offset : 12;	//�ض�λ��ƫ��
		unsigned short type : 4;	//�ض�λ������
	}TYPE, *PTYPE;
	CPe();
	~CPe();
	//��ȡԭOEP
	DWORD GetOep();
	//��ȡĿ���ļ�
	void ReadTargetFile(char* pPath);
	//�������	����������,����������,�����εĴ�С,����������
	void AddSection(PCHAR pName, PCHAR pSectionBuf, DWORD dwSectionSize, DWORD dwAttribute);
	//�����
	DWORD CalcAlignment(DWORD dwSize, DWORD dwAlignment);
	//����ӿǺ���ļ�
	void SaveNewFile(char* pPath);
	//�޸��ض�λ
	void FixRloc(PCHAR pBuf);
	//void FixRloc();
	DWORD GetNewSectionRVA();
	//��ȡ������RVA
	DWORD GetNewSectionRva();
	//����
	void Encrypt();
	//ȥ�������ַ
	void CancleRandomBase();
	//������OEP
	void SetNewOep(DWORD dwNewOep);
	//ѹ��
	void Compress(PPACKINFO pPackInfo);
	//�޸�INT��
	void FixINT(PCHAR pBuf);
private:
	//��
	PCHAR m_pBuf;		//����Ŀ��ռ�
	DWORD m_dwFileSize;	//�ļ���С
	//��
	DWORD m_dwNewFileSize;//����
	PCHAR m_pNewBuf;
	PIMAGE_DOS_HEADER m_pDos;
	PIMAGE_NT_HEADERS m_pNt;
	PIMAGE_SECTION_HEADER m_pSection;
public:
	DWORD m_dwPackInfoOffset;		//PACKINFO���ص��ڴ��ƫ��
};


