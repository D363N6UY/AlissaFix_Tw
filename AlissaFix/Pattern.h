// Anyone affiliated with Nexon is not allowed to view this file.
// I am not responsible for any misuse of this source code or the binary file.

/* Change log:
2013/1/10 Initial Version
2013/5/17 Updated to R149 
	- mint::CMessage::ReadFromNetworkBuffer
	- mint::CVirtualMachine::Post
2013/9/17 Everything is changed

2017/6/28 Tw R266 Fixed
*/

#include "PatternSearch.h"

LPTSTR patternVersion = L"Pattern version 2017/6/28 R266 Tw\n";
LPTSTR patternVersionc = L"ª©¥» 2017/6/28 R256 Tw\n";

//sendhookee is called at offset +0x27 of the pattern location below
int sendhookeeOffset = 0x47;
char* sendhookeeCaller = "558BEC6AFF68????????64A100000000505153A1????????33C5508D????64A30000000033DB89????83????8D????8BCC8965F050E8????????C645FC018B0D????????88????E8????????8AD8C745FCFFFFFFFF8D????E8????????8AC38B????64890D????????595B8BE55DC20C00";



char* TCMessage = "558BEC6AFF68????????64A1000000005051A1????????33C5508D45F464A300000000894DF08B45F0C700????????C745FC000000008B4DF0E8????????";



char* getStreamLength_pat = "558BEC83EC0856894DF868????????E9????????";

char* WriteToNetworkBuffer_Pat = "558BEC83EC60535657894DA068????????";

//we want a pointer to ?s_pInstanceBlock@?$TSingleton@VCVirtualMachine@mint@@@esl@@0PAEA
//original dinput8 use mint::CVirtualMachine::GetInstance() to get it but this function is too short and
//can't be searched. So we search for another function that references this pointer. 
//vminstance reference offset to the pattern is -0x53
int VMInstanceRefOffset = -0x3B;
pattern VMInstanceRef = {L"VMInstanceRef", 6, 12, {0,1,2,3,4,5,6,7,8,9,-0x3B,-0x3A},
{
			 0x59,              
		     0x5F, 0x5E,         
             0x5B, 0x8B,
             0xE5,
		     0x5D,               
		     0xC2,              
		     0x04, 0x00,       
		     0x8B, 0x3D			
}};			


int CMessageCallerOffset = 0xb;
pattern CMessageCaller = {L"CMessageCaller", 8, 12, {0,1,2,3,4,5,6,7,8,9,10,11},
{
	0x83, 0xC1, 0xFA,                    
	0x51,                                 
	0x83, 0xC0, 0x06,                     
	0x50,                                 
	0x8D, 0x4D, 0xE4,                     
	0xE8								 
}};

int ReadFromNetworkBufCallerOffset = 0xd;
pattern ReadFromNetworkBufCallerCaller = {L"ReadFromNetworkBufCallerCaller", 9, 14, {0,1,2,3,4,5,6,7,8,9,10,11,12,13},
{
	0xB3, 0x03, 0x88, 0x5D,                    
	0xFC, 0x8B, 0x55,                         
	0xEC,                                    
	0x52,
	0x56, 0x8D, 0x4D,                   
	0xD4, 0xE8                                     
}};


///////////////////////////////////////////////////////////////////////////////////
pattern ntdll_76f58954 = {L"ntdll_76f58954", 100, 17, {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}, 
{0x55,0x8b,0xec,0x56,0x57,0x53,0x8b,0xf4,0xFF,0x75,0x14,0xFF,0x75,0x10,0xFF,0x75,0x0c}};

pattern fixBlade = {L"fixBlade", 101, 6, {0,1,8,9,10,11},{0x72,0x37,0x6a,0x00,0x6a,0xff}};