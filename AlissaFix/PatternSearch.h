#pragma once
#include "stdafx.h"


struct pattern{
	LPTSTR name;
	int id;
	int checkPoints;
	int offset[32];
	BYTE bytePattern[32];
};


class CPatternSearch
{
public:
	CPatternSearch(DWORD start, DWORD end, pattern p);
	CPatternSearch(DWORD start, DWORD end, int bSize, BYTE* _bytePattern, int* _offset);
	~CPatternSearch(void);
	void Search();
	DWORD BytePatternSearch();
	DWORD BytePatternSearchEx();
	TCHAR lpszname[MAX_PATH];
	int id;
	int checkPoints;
	int* offset;
	BYTE* bytePattern;
	DWORD address;

	DWORD searchPOS;
	DWORD searchEnd;
};

