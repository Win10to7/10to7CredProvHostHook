// CredProvHostHook.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "CredProvHostHook.h"


// This is an example of an exported variable
CREDPROVHOSTHOOK_API int nCredProvHostHook=0;

// This is an example of an exported function.
CREDPROVHOSTHOOK_API int fnCredProvHostHook(void)
{
    return 0;
}

// This is the constructor of a class that has been exported.
CCredProvHostHook::CCredProvHostHook()
{
    return;
}
