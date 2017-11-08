#pragma once

#include<windows.h>
#include "..\Stub\stub.h"
// 使用该压缩库包含需要下面3条编译预处理指令
#define ZLIB_WINAPI
#include "zlib/zlib.h"
#pragma comment(lib,"zlib/zlibstat.lib")


class CPe
{
public:
	typedef struct _TYPE
	{
		unsigned short offset : 12;	//重定位的偏移
		unsigned short type : 4;	//重定位的属性
	}TYPE, *PTYPE;
	CPe();
	~CPe();
	//获取原OEP
	DWORD GetOep();
	//读取目标文件
	void ReadTargetFile(char* pPath);
	//添加区段	新区段名称,新区段内容,新区段的大小,新区段属性
	void AddSection(PCHAR pName, PCHAR pSectionBuf, DWORD dwSectionSize, DWORD dwAttribute);
	//对齐块
	DWORD CalcAlignment(DWORD dwSize, DWORD dwAlignment);
	//保存加壳后的文件
	void SaveNewFile(char* pPath);
	//修复重定位
	void FixRloc(PCHAR pBuf);
	//void FixRloc();
	DWORD GetNewSectionRVA();
	//获取新区段RVA
	DWORD GetNewSectionRva();
	//加密
	void Encrypt();
	//去除随机基址
	void CancleRandomBase();
	//设置新OEP
	void SetNewOep(DWORD dwNewOep);
	//压缩
	void Compress(PPACKINFO pPackInfo);
	//修复INT表
	void FixINT(PCHAR pBuf);
private:
	//旧
	PCHAR m_pBuf;		//接收目标空间
	DWORD m_dwFileSize;	//文件大小
	//新
	DWORD m_dwNewFileSize;//对齐
	PCHAR m_pNewBuf;
	PIMAGE_DOS_HEADER m_pDos;
	PIMAGE_NT_HEADERS m_pNt;
	PIMAGE_SECTION_HEADER m_pSection;
public:
	DWORD m_dwPackInfoOffset;		//PACKINFO加载到内存的偏移
};


