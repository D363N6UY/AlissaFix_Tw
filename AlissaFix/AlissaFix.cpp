// Anyone affiliated with Nexon is not allowed to view this file.
// I am not responsible for any misuse of this source code or the binary file.
// Contact: 156062223@qq.com

#include "stdafx.h"
#include "AlissaFix.h"
#include "PatternSearch.h"
#include "Pattern.h"
#include "WCHAR.h"
#include "windns.h"
//#include "Hook.h"
#include "resource.h"
#include "winuser.h"

WCHAR* version = L"                 *** AlissaFix 2017/07/13 by me *** \n";
WCHAR* title = L"AlissaFix";
int debugMode = 0;
bool showAddr = 1;
bool autoExit = 0;
bool isX64 = 0;
HWND hwndClient;
HANDLE hConsoleW, hConsoleR;
HMODULE pakeBase;
enum Color {black = 0, blue, green, cyan, red, purple, yellow, grey, dgrey, lblue, lgreen, lcyan, lred, lpurple, lyellow, white};
DWORD SendHookeeAddr = 0, TCMessageAddr = 0, CMessageAddr = 0, GetStreamLengthAddr = 0, WriteToNetworkBufferAddr = 0,
	ReadFromNetworkBufferAddr = 0, VMInstanceRefAddr = 0, VM_Instance = 0, VMPostAddr = 0;
BYTE SendHookeeRecovery[5] = {0};
BYTE ReadFromNetworkBufferRecovery[9] = {0};
DWORD SendHookAddr, SendHookRecoveryAddr, RecvHookAddr, RecvHookRecoveryAddr;

//BYTE* pRecovery;
//bool bfixBlade = 0;
//CHook* hook_ntdll_76f58954;

BYTE HexCharacterToByte(char hex)
{
	BYTE result = (BYTE)hex;
	if(result >= 97)		 //This is a b c d e f
		result -= 87;
	else if (result >= 65)   //This is A B C D E F   
		result -= 55;   //Ascii A is 65. therefore -55 will give us numeric hex
	else if (result >= 48)   //This is 0-9
		result -= 48;   //Ascii 0 is 48. therefore -48 will give us numeric hex
	return result;
}

extern "C" ALISSAFIX_API DWORD PatternSearch(DWORD start, DWORD end, char* szPtn, bool checkMulti){
	if ((strlen(szPtn) % 2) != 0)
		return 1;		//1 means the number of characters in string is not even
	if (start == 0)
		start = 0x401000;
	if (end == 0)
		end = 0x3000000;
	int size = 0;
	//count number of ?'s
	for(int i = 0; i < (strlen(szPtn) - 1); ++i){
		if(szPtn[i] == '?')
			++size;
	}
	size = strlen(szPtn) - size;	//number of non ? characters
	size /= 2;			//number of bytes
	int* offset = new int[size];
	BYTE* bytePattern = new BYTE[size];
	BYTE hi, lo;
	for(int i = 0, j = 0; j < size; i += 2, ++j){	//i is character index, j is counter
		if(szPtn[i] == '?'){
			--j;		//encounter ?, do not increment counter
			continue;
		}
		if(isxdigit(szPtn[i]) == 0 || isxdigit(szPtn[i + 1]) == 0){	//if encounter invalid digit, return
			delete[] offset;
			delete[] bytePattern;
			return 2;	// 2 means the string contains invalid character
		}
		hi = HexCharacterToByte(szPtn[i]);
		hi *= 16;
		lo = HexCharacterToByte(szPtn[i + 1]);
		hi += lo;
		offset[j] = i / 2;
		bytePattern[j] = hi;	//insert the byte element
	}
	CPatternSearch p(start, end, size, bytePattern, offset);
	if(!checkMulti)
		return p.BytePatternSearch();
	return p.BytePatternSearchEx();
} 

extern "C" ALISSAFIX_API void ConsoleOutput(WCHAR* szMessage, DWORD color = white){
	int len = wcslen(szMessage);
	DWORD numOfCharWritten;
	SetConsoleTextAttribute(hConsoleW, color);
	WriteConsole(hConsoleW, szMessage, len, &numOfCharWritten, NULL);
}

void PatternSearchLogSuccess(WCHAR* address){
	if (!showAddr)
		address = L"Ok";
	ConsoleOutput(L"	[");
	ConsoleOutput(address, green);
	ConsoleOutput(L"]\n");
}

void PatternSearchLogFailure(WCHAR* err){
	ConsoleOutput(L"	[");
	ConsoleOutput(err, lred);
	ConsoleOutput(L"]\n");
}

bool GetAccessRight(DWORD addr, int length)
{
	DWORD newProtect = PAGE_EXECUTE_READWRITE;
	DWORD oldProtect;
	bool ok = VirtualProtect((void*)addr, length, newProtect, &oldProtect);
	return ok;
}

DWORD GetVMInstance(){
	return *(DWORD*)VM_Instance;
}

__declspec(naked) void GetReceiverId(){
	__asm
	{
		mov     ecx, [ecx+8]
		test    ecx, ecx
		jnz     LABLE1
		xor     eax, eax
		xor     edx, edx
		retn
	LABLE1:                          
		mov     eax, [ecx+10h]
		mov     edx, [ecx+14h]
		retn
	}
} 

void PatchDinput8(){
	//Patch SendHook
	//Update function pointers in dinput8 for SendHook
	*(DWORD*)((DWORD)pakeBase + 0x2FFE8) = TCMessageAddr;
	*(DWORD*)((DWORD)pakeBase + 0x2FFF0) = GetStreamLengthAddr;
	*(DWORD*)((DWORD)pakeBase + 0x2FFF4) = WriteToNetworkBufferAddr;
	GetAccessRight(SendHookRecoveryAddr, 5);
	//Write recovery code before jumping back to sendhookee
	memcpy((PVOID)SendHookRecoveryAddr, SendHookeeRecovery, 5);
	//Write jump back address
	*(DWORD*)((DWORD)pakeBase + 0x2FFFC) = SendHookeeAddr + 5;
	//­×¥¿OPCODE°¾²¾ RECV+4A 
	//*(BYTE*)((DWORD)pakeBase + 0x121CD) = 0x3C;
	//­×¥¿OPCODE°¾²¾ RECV+65
	//*(BYTE*)((DWORD)pakeBase + 0x121E5) = 0x40;
	//Now patch RecvHook
	GetAccessRight(RecvHookRecoveryAddr , 18);
	memcpy((PVOID)(RecvHookRecoveryAddr + 9), (PVOID)(RecvHookRecoveryAddr + 6), 12);
	//Write recovery code before jumping back
//	GetAccessRight(RecvHookRecoveryAddr, 0);
	memcpy((PVOID)RecvHookRecoveryAddr, ReadFromNetworkBufferRecovery, 9);
	//Write jump back address
	*(DWORD*)((DWORD)pakeBase + 0x2FFF8) = ReadFromNetworkBufferAddr + 9;
	//Now patch VMHook
	*(DWORD*)((DWORD)pakeBase + 0x2FFDC) = (DWORD)GetVMInstance;
	*(DWORD*)((DWORD)pakeBase + 0x2FFE0) = VMPostAddr;
	*(DWORD*)((DWORD)pakeBase + 0x2FFE4) = CMessageAddr;
	*(DWORD*)((DWORD)pakeBase + 0x2FFEC) = (DWORD)GetReceiverId;
}

void PatchClient(){
	//sendhookee, write jump to dinput8
	
	memcpy(SendHookeeRecovery, (PVOID)SendHookeeAddr, 5);	//read in recovery code
	int offset = SendHookAddr - SendHookeeAddr - 5;
	
	*(BYTE*)SendHookeeAddr = 0xE9;
	*(DWORD*)(SendHookeeAddr + 1) = offset;
	
	//ReadFromNetworkBuffer, write jump to dinput8
	
	if(ReadFromNetworkBufferAddr != 0){
		memcpy(ReadFromNetworkBufferRecovery, (PVOID)ReadFromNetworkBufferAddr, 9);  //read in recovery code
		offset = RecvHookAddr - ReadFromNetworkBufferAddr - 5;
		*(BYTE*)ReadFromNetworkBufferAddr = 0xE9;
		*(DWORD*)(ReadFromNetworkBufferAddr + 1) = offset;
		*(DWORD*)(ReadFromNetworkBufferAddr + 5) = 0x90909090;
	}
}

//Converts Dword address vaule to WCHAR* string
WCHAR* DwordToWSTR(DWORD address){
	static WCHAR lpszAddress[11] = {0};
	wsprintf(lpszAddress, L"0x%08x",address);
	return lpszAddress;
}

extern "C" ALISSAFIX_API WCHAR* WaitUserResponse(TCHAR* moduleName){
	FlushConsoleInputBuffer(hConsoleR);
	ConsoleOutput(moduleName, lcyan);
	static WCHAR buffer[256];
	DWORD NumberOfCharsRead = 0;
	ReadConsoleW(hConsoleR, buffer, 256, &NumberOfCharsRead, NULL);
	buffer[NumberOfCharsRead - 2] = 0;
	return buffer;
}

void ErrorExit(WCHAR* message){
	ConsoleOutput(message, lred);
	ConsoleOutput(L"Press enter to close this window.");
	WaitUserResponse(L">AF ");
	FreeConsole();
}

bool CheckPatternSearchSuccess(DWORD address){
	if (address > 10)
	{
		PatternSearchLogSuccess(DwordToWSTR(address));
		return 1;
	}
	else {
		WCHAR code[11];
		WCHAR err[24] = L"Fail: ";
		wsprintf(code, L"%d", address);
		wcscat(err, code);
		PatternSearchLogFailure(err);
		return 0;
	}
}

bool PatternSearch(){
	bool ok = 1;
	ConsoleOutput(L"\nPattern Searching...");
	ConsoleOutput(patternVersionc);
	ConsoleOutput(L"SendHookee		", lyellow);
	//Call operand = destination - current addr - 5
	//from call operand to call destination:
	//destination = Call operand + current addr + 5
	DWORD sendhookeeCallerAddr = PatternSearch(0, 0, sendhookeeCaller, 1);
	if (sendhookeeCallerAddr)
	{
		sendhookeeCallerAddr += sendhookeeOffset;
		DWORD callOperand = *(DWORD*)(sendhookeeCallerAddr + 1);
		SendHookeeAddr = callOperand + sendhookeeCallerAddr + 5;
		CheckPatternSearchSuccess(SendHookeeAddr);
	}
	else{
		CheckPatternSearchSuccess(sendhookeeCallerAddr);
		ErrorExit(L"SendHookee not found. This version of AlissaFix won't work :(\n");
		return 0;
	}

	ConsoleOutput(L"mint::CMessage::~CMessage", lyellow);
	TCMessageAddr = PatternSearch(0, 0, TCMessage, 1);
	if(!CheckPatternSearchSuccess(TCMessageAddr)){
		ok = 0;
	}

	ConsoleOutput(L"mint::CMessage::CMessage", lyellow);
	CPatternSearch ptnCMessageCaller(0, 0, CMessageCaller);
	DWORD CMessageCallerAddr = ptnCMessageCaller.BytePatternSearchEx();
	if(CMessageCallerAddr){
		CMessageCallerAddr += CMessageCallerOffset;
		DWORD callOperand = *(DWORD*)(CMessageCallerAddr + 1);
		CMessageAddr = callOperand + CMessageCallerAddr + 5;
		CheckPatternSearchSuccess(CMessageAddr);
	}
	else{
		CheckPatternSearchSuccess(CMessageCallerAddr);
		ok = 0;
	}
	
	ConsoleOutput(L"mint::CMessage::ReadFromNetworkBuffer", lyellow);
	CPatternSearch ptnReadFromNetworkBufCaller(0, 0, ReadFromNetworkBufCallerCaller);
	DWORD ReadFromNetworkBufCallerAddr = ptnReadFromNetworkBufCaller.BytePatternSearchEx();
	if(ReadFromNetworkBufCallerAddr){
		ReadFromNetworkBufCallerAddr += ReadFromNetworkBufCallerOffset;
		DWORD callOperand = *(DWORD*)(ReadFromNetworkBufCallerAddr + 1);
		ReadFromNetworkBufferAddr = callOperand + ReadFromNetworkBufCallerAddr + 5;
		CheckPatternSearchSuccess(ReadFromNetworkBufferAddr);
	}
	else{
		CheckPatternSearchSuccess(ReadFromNetworkBufCallerAddr);
		ok = 0;
	}

	ConsoleOutput(L"mint::CMessage::GetStreamLength	", lyellow);
	GetStreamLengthAddr = PatternSearch(0, 0, getStreamLength_pat, 1);
	if (!CheckPatternSearchSuccess(GetStreamLengthAddr)) {
		ok = 0;
	}

	ConsoleOutput(L"mint::CMessage::WriteToNetworkBuffer	", lyellow);
	WriteToNetworkBufferAddr = PatternSearch(0, 0, WriteToNetworkBuffer_Pat, 1);
	if (!CheckPatternSearchSuccess(WriteToNetworkBufferAddr)) {
		ok = 0;
	}

	ConsoleOutput(L"esl::TSingleton<mint::CVirtualMachine>::GetInstance\n", lyellow);
	ConsoleOutput(L"	-Ref		", lyellow);
	CPatternSearch ptnVMInstanceRef(0, 0, VMInstanceRef);
	VMInstanceRefAddr = ptnVMInstanceRef.BytePatternSearch();
	if(CheckPatternSearchSuccess(VMInstanceRefAddr)){
		VMInstanceRefAddr += VMInstanceRefOffset;
		//found VMInstanceRef. Now read the operand of that instruction to get VM_Instance
		VM_Instance = *(DWORD*)(VMInstanceRefAddr + 2);
		ConsoleOutput(L"	-VMInstance	", lyellow);
		CheckPatternSearchSuccess(VM_Instance);
	}
	else
		ok = 0;
	return ok;
}

void UseDllAPI(){
	ConsoleOutput(L"\n¸ü¤JDLL...\n");
	LoadLibrary(L"ESL.dll");
	HMODULE hMint= LoadLibrary(L"Mint.dll");
	//GetStreamLengthAddr = (DWORD)GetProcAddress(hMint, "?GetStreamLength@CMessage@mint@@QBEKXZ");
	//WriteToNetworkBufferAddr = (DWORD)GetProcAddress(hMint, "?WriteToNetworkBuffer@CMessage@mint@@QAEKPAXK@Z");
	VMPostAddr = (DWORD)GetProcAddress(hMint, "?Post@CVirtualMachine@mint@@QAE_N_KVCMessage@2@@Z");

	//ConsoleOutput(L"mint::CMessage::GetStreamLength	", lyellow);
	//CheckPatternSearchSuccess(GetStreamLengthAddr);

	//ConsoleOutput(L"mint::CMessage::WriteToNetworkBuffer", lyellow);
	//CheckPatternSearchSuccess(WriteToNetworkBufferAddr);

	ConsoleOutput(L"mint::CVirtualMachine::Post", lyellow);
	CheckPatternSearchSuccess(VMPostAddr);
}

//void _FixBlade(DWORD, DWORD bladeEntry, DWORD bladeBase, DWORD fdwReason, DWORD lpvReserved, DWORD, DWORD, WCHAR* moduleName){
//	if ((DWORD)moduleName <= 1000)
//		return;
//	if(wcscmp(moduleName,L"DSOUND.DLL") == 0){
//		CPatternSearch ptnFixBlade((DWORD)(bladeBase + 0x1000), (DWORD)(bladeBase + 0x6000), fixBlade);
//		DWORD patchPoint = ptnFixBlade.BytePatternSearchEx();
//		if (patchPoint > 1250){
//			GetAccessRight(patchPoint, 1);
//			*(BYTE*)patchPoint = 0xeb;
//			bfixBlade = 1;
//		}
//	}
//}
//
//__declspec(naked) void FixBlade(){
//	__asm{
//		call _FixBlade
//		jmp pRecovery
//	}
//}
//
//void Blade(){
//	DWORD ntdllBase = (DWORD)GetModuleHandle(L"ntdll.dll");
//	DWORD ntdll_76f58954Addr = 0;
//	if(isX64){
//		CPatternSearch ptnNtdll_76f58954(ntdllBase + 0x10000, ntdllBase + 0xd6000, ntdll_76f58954);
//		ntdll_76f58954Addr =  ptnNtdll_76f58954.BytePatternSearchEx();
//	}
//	else{
//		CPatternSearch ptnNtdll_76f58954(ntdllBase + 0x1000, ntdllBase + 0xd5000, ntdll_76f58954);
//		ntdll_76f58954Addr =  ptnNtdll_76f58954.BytePatternSearchEx();
//	}
//	if(ntdll_76f58954Addr < 0x5000)
//		return;
//	hook_ntdll_76f58954 = new CHook(ntdll_76f58954Addr, (DWORD)FixBlade, 5);
//	pRecovery = hook_ntdll_76f58954->recovery;
//	hook_ntdll_76f58954->Hook();
//}

int init(){	
	//check x64
	SYSTEM_INFO sysInfo;
	GetNativeSystemInfo(&sysInfo);
	if(sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
		isX64 = 1;
	//create console window
	AllocConsole();
	SetConsoleTitle(title);
	HWND hwndConsole = GetConsoleWindow();
	SendMessage(hwndConsole, WM_SETICON, ICON_SMALL, (LPARAM)LoadIcon(GetModuleHandleA("AlissaFix.dll"), MAKEINTRESOURCE(IDI_ICON1))); 
	hConsoleW = GetStdHandle(STD_OUTPUT_HANDLE);
	hConsoleR = GetStdHandle(STD_INPUT_HANDLE);
	SetConsoleMode(hConsoleR, ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT | ENABLE_ECHO_INPUT);
	COORD size = {80, 1500};
	SetConsoleScreenBufferSize(hConsoleW, size);
	ConsoleOutput(L"===============================================================================\n", dgrey);
	ConsoleOutput(version, lpurple);
	ConsoleOutput(L"===============================================================================\n", dgrey);
	//Blade();
	//wait for themida to unpack
	if (debugMode == 0){
		ConsoleOutput(L"Wait 3 seconds for themida to unpack.\n");
		Sleep(3000);
	}
	else{
		ConsoleOutput(L"Wait a few seconds for themida to unpack and then press enter.\n");
		WaitUserResponse(L">AF ");
	}
	UseDllAPI();
	//start pattern search
	bool ok = PatternSearch();

	//Start patching
	ConsoleOutput(L"\nPatching...\n");
	pakeBase = GetModuleHandleA("dinput8.dll");
	if(pakeBase == NULL){
		ErrorExit(L"Can't find dinput8.dll.\nAborted.\n");
		return 0;
	}

	//Get function addresses in dinput8
	//Jump to here from sendhookee
	SendHookAddr = (DWORD)pakeBase + 0x121c0;
	//The first 2 instructions in sendhookee is recovered here before jumping back
	SendHookRecoveryAddr = (DWORD)pakeBase + 0x12251;
	//Jump to here from ReadFromNetworkBuffer
	RecvHookAddr = (DWORD)pakeBase + 0x12520;
	//The first 3 instructions in ReadFromNetworkBuffer is recovered here before jumping back
	RecvHookRecoveryAddr = (DWORD)pakeBase + 0x122c0;
	PatchClient();
	PatchDinput8();

	//if (bfixBlade)
	//	ConsoleOutput(L"Abyss compatibility fixed :)", green);

	ConsoleOutput(L"\nAll done!\n", green);
	SetConsoleTextAttribute(hConsoleW, FOREGROUND_RED);
	ConsoleOutput(L"===============================================================================\n", dgrey);
	//InitExtra();
	ConsoleOutput(L"===============================================================================\n", dgrey);
	if (ok && autoExit) {
		ConsoleOutput(L"Auto closing in 8 seconds...");
		Sleep(8000);
		FreeConsole();
		//hook_ntdll_76f58954->UnHook();
		//delete hook_ntdll_76f58954;
		return 1;
	}
	ConsoleOutput(L"Press enter to close this window.\n");
	//WaitUserResponse(L">AF ");
	FreeConsole();
	//hook_ntdll_76f58954->UnHook();
	//delete hook_ntdll_76f58954;
	return 0;
}

