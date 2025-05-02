// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the CREDPROVHOSTHOOK_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// CREDPROVHOSTHOOK_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef CREDPROVHOSTHOOK_EXPORTS
#define CREDPROVHOSTHOOK_API __declspec(dllexport)
#else
#define CREDPROVHOSTHOOK_API __declspec(dllimport)
#endif

// This class is exported from the dll
class CREDPROVHOSTHOOK_API CCredProvHostHook {
public:
	CCredProvHostHook(void);
	// TODO: add your methods here.
};

extern CREDPROVHOSTHOOK_API int nCredProvHostHook;

CREDPROVHOSTHOOK_API int fnCredProvHostHook(void);
