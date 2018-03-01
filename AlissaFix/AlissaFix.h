// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the ALISSAFIX_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// ALISSAFIX_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef ALISSAFIX_EXPORTS
#define ALISSAFIX_API __declspec(dllexport)
#else
#define ALISSAFIX_API __declspec(dllimport)
#endif

int init();
bool GetAccessRight(DWORD addr, int length);
void InitExtra();
