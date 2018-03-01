/*Pattern searching class library
by 0x64
v0.1 2012/6/18
v0.2 2013/5/25
*/

#include "StdAfx.h"
#include "PatternSearch.h"


CPatternSearch::CPatternSearch(DWORD start, DWORD end, pattern p)
{
	id = p.id;
	checkPoints = p.checkPoints;

	wcscpy(lpszname, p.name);
	offset = new int[sizeof(p.offset) / 4];
	memcpy(offset, p.offset, sizeof(p.offset));

	bytePattern = new BYTE[sizeof(p.bytePattern)];
	memcpy(bytePattern, p.bytePattern, sizeof(p.bytePattern));
	address = 0;
	if (start == 0)
		searchPOS = 0x401000;	//start address
	else
		searchPOS = start;
	if (end == 0)
		searchEnd = 0x3000000;	//end address
	else
		searchEnd = end;
}

CPatternSearch::CPatternSearch(DWORD start, DWORD end, int bSize, BYTE* _bytePattern, int* _offset)
{
	checkPoints = bSize;
	bytePattern = _bytePattern;
	offset = _offset;
	address = 0;
	searchPOS = start;
	searchEnd = end;
}

CPatternSearch::~CPatternSearch(void)
{
	delete[] offset;
	delete[] bytePattern;
}

DWORD CPatternSearch::BytePatternSearch()
{	
	int CheckIndex = 0;
	for (searchPOS; searchPOS < searchEnd; searchPOS++){
		while (1){
			if (CheckIndex == checkPoints)
				return searchPOS;  //All matched, return first checkpoint address
			if (*(BYTE*)(searchPOS + offset[CheckIndex]) == bytePattern[CheckIndex])
				CheckIndex++;
			else 
				break;
		}
		CheckIndex = 0;	//Not matched. Start over
	}
	return 0;
}

DWORD CPatternSearch::BytePatternSearchEx()
{
	DWORD result = 0, result2 = 0;
	result = BytePatternSearch();
	if (result == 0)
		return 0;
	searchPOS = result + 1;
	result2 = BytePatternSearch();
	if(result2 == 0)
		return result;
	return 3;
}

