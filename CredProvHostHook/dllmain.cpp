// dllmain.cpp : Defines the entry point for the DLL application.
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#define INITGUID
// Windows Header Files
#include <windows.h>
#include <hstring.h>
#include <pplwin.h>
#define DllGetClassObject KYS1
#define DllCanUnloadNow KYS2
#include <unknwnbase.h>
#undef DllGetClassObject
#undef DllCanUnloadNow
#include "MinHook.h"

DEFINE_GUID(GUID_7a872d34_bc6b_4f83_b199_22e9c0a91ddc, 0x7A872D34, 0xBC6B, 0x4F83, 0xB1, 0x99, 0x22, 0xE9, 0xC0, 0xA9, 0x1D, 0xDC);
DEFINE_GUID(GUID_c5874d2e_5a87_48c4_a7d3_6fbb7e8da746, 0xC5874D2E, 0x5A87, 0x48C4, 0xA7, 0xD3, 0x6F, 0xBB, 0x7E, 0x8D, 0xA7, 0x46);

//new
DEFINE_GUID(GUID_2d6268a8_e4ba_4547_84f7_5aab881163b5, 0x2D6268A8, 0xE4BA, 0x4547, 0x84, 0xF7, 0x5A, 0xAB, 0x88, 0x11, 0x63, 0xB5);

#define CREDENTIAL_SCENARIO int
#define SUPPORTED_UI_FEATURE_FLAGS int
#define _CREDENTIAL_PROVIDER_USAGE_SCENARIO int
#define CREDENTIALSCHANGED_STATE int
#define TILE_SELECTION_FLAGS int
#define _CREDENTIAL_PROVIDER_DISPLAY_STATE_FLAGS int

class CCredentialProviderFrameworkNew
{
public:
    virtual HRESULT STDMETHODCALLTYPE QueryInterface(_GUID const&, void**) PURE;
    virtual HRESULT STDMETHODCALLTYPE AddRef(void) PURE;
    virtual HRESULT STDMETHODCALLTYPE Release(void) PURE;
    virtual HRESULT STDMETHODCALLTYPE InitializeAsync(CREDENTIAL_SCENARIO, SUPPORTED_UI_FEATURE_FLAGS, void*, void*, USHORT) PURE;
    virtual HRESULT STDMETHODCALLTYPE StartCredProvsAsync(_CREDENTIAL_PROVIDER_USAGE_SCENARIO, ULONG, void*, _GUID const*, UCHAR const*, UINT, USHORT const*) PURE;
    virtual HRESULT STDMETHODCALLTYPE AdviseCredProvsAsync(void) PURE;
    virtual HRESULT STDMETHODCALLTYPE EnumerateAllCredentialsAsync(void) PURE;
    virtual HRESULT STDMETHODCALLTYPE EnumerateTilesForProviderAsync(UINT, CREDENTIALSCHANGED_STATE) PURE;
    virtual HRESULT STDMETHODCALLTYPE AdviseCredentialAsync(UINT, UINT, HWND__*) PURE;
    virtual HRESULT STDMETHODCALLTYPE SelectCredentialAsync(UINT, UINT, TILE_SELECTION_FLAGS) PURE;
    virtual HRESULT STDMETHODCALLTYPE GetSerializationAsync(UINT, UINT, void*) PURE;
    virtual HRESULT STDMETHODCALLTYPE GetPicturePasswordSerializationAsync(UINT, UINT, void*, void*) PURE;
    virtual HRESULT STDMETHODCALLTYPE ReportResultAsync(UINT, long, long, USHORT const*, USHORT const*, USHORT const*) PURE;
    virtual HRESULT STDMETHODCALLTYPE SetStringDataAsync(UINT, UINT, ULONG, USHORT const*) PURE;
    virtual HRESULT STDMETHODCALLTYPE OnCommandLinkClickedAsync(UINT, UINT, ULONG) PURE;
    virtual HRESULT STDMETHODCALLTYPE SetCheckboxValueAsync(UINT, UINT, ULONG, int) PURE;
    virtual HRESULT STDMETHODCALLTYPE SetComboBoxValueAsync(UINT, UINT, ULONG, ULONG) PURE;
    virtual HRESULT STDMETHODCALLTYPE DisconnectCredentialsAsync(void) PURE;
    virtual HRESULT STDMETHODCALLTYPE BuildUserTileAsync(_CREDENTIAL_PROVIDER_USAGE_SCENARIO) PURE;
    virtual HRESULT STDMETHODCALLTYPE SetDisplayStateAsync(_CREDENTIAL_PROVIDER_DISPLAY_STATE_FLAGS) PURE;
    virtual HRESULT STDMETHODCALLTYPE UnadviseCredentialAsync(UINT, UINT) PURE;
    virtual HRESULT STDMETHODCALLTYPE UnadviseCredProvsAsync(void) PURE;
    virtual HRESULT STDMETHODCALLTYPE Shutdown(void) PURE;
    virtual HRESULT STDMETHODCALLTYPE CheckProviderAvailability(_CREDENTIAL_PROVIDER_USAGE_SCENARIO, ULONG, USHORT const*, int*) PURE;
    virtual HRESULT STDMETHODCALLTYPE OnWebDialogVisibilityChangeAsync(UINT, UINT, int) PURE;
    virtual HRESULT STDMETHODCALLTYPE SetUserSuggestionAsync(USHORT const*) PURE;
    virtual HRESULT STDMETHODCALLTYPE DTR() PURE;
};

class CCredentialProviderFrameworkWrapper
{
public:

    CCredentialProviderFrameworkWrapper(CCredentialProviderFrameworkNew* actualInstance);

    CCredentialProviderFrameworkNew* m_actualInstance;
    long m_cRef;

    virtual HRESULT STDMETHODCALLTYPE QueryInterface(_GUID const&, void**);
    virtual HRESULT STDMETHODCALLTYPE AddRef(void);
    virtual HRESULT STDMETHODCALLTYPE Release(void);
    virtual HRESULT STDMETHODCALLTYPE InitializeAsync(CREDENTIAL_SCENARIO, void*, void*, USHORT);
    virtual HRESULT STDMETHODCALLTYPE StartCredProvsAsync(_CREDENTIAL_PROVIDER_USAGE_SCENARIO, ULONG, void*, _GUID const*, UCHAR const*, UINT);
    virtual HRESULT STDMETHODCALLTYPE AdviseCredProvsAsync(void);
    virtual HRESULT STDMETHODCALLTYPE EnumerateAllCredentialsAsync(void);
    virtual HRESULT STDMETHODCALLTYPE EnumerateTilesForProviderAsync(UINT, CREDENTIALSCHANGED_STATE);
    virtual HRESULT STDMETHODCALLTYPE AdviseCredentialAsync(UINT, UINT, HWND__*);
    virtual HRESULT STDMETHODCALLTYPE SelectCredentialAsync(UINT, UINT, TILE_SELECTION_FLAGS);
    virtual HRESULT STDMETHODCALLTYPE GetSerializationAsync(UINT, UINT, void*);
    virtual HRESULT STDMETHODCALLTYPE GetPicturePasswordSerializationAsync(UINT, UINT, void*, void*);
    virtual HRESULT STDMETHODCALLTYPE ReportResultAsync(UINT, long, long, USHORT const*);
    virtual HRESULT STDMETHODCALLTYPE SetStringDataAsync(UINT, UINT, ULONG, USHORT const*);
    virtual HRESULT STDMETHODCALLTYPE OnCommandLinkClickedAsync(UINT, UINT, ULONG);
    virtual HRESULT STDMETHODCALLTYPE SetCheckboxValueAsync(UINT, UINT, ULONG, int);
    virtual HRESULT STDMETHODCALLTYPE SetComboBoxValueAsync(UINT, UINT, ULONG, ULONG);
    virtual HRESULT STDMETHODCALLTYPE DisconnectCredentialsAsync(void);
    virtual HRESULT STDMETHODCALLTYPE BuildUserTileAsync(_CREDENTIAL_PROVIDER_USAGE_SCENARIO);
    virtual HRESULT STDMETHODCALLTYPE SetDisplayStateAsync(_CREDENTIAL_PROVIDER_DISPLAY_STATE_FLAGS);
    virtual HRESULT STDMETHODCALLTYPE UnadviseCredentialAsync(UINT, UINT);
    virtual HRESULT STDMETHODCALLTYPE UnadviseCredProvsAsync(void);
    virtual HRESULT STDMETHODCALLTYPE Shutdown(void);
    virtual HRESULT STDMETHODCALLTYPE CheckProviderAvailability(_CREDENTIAL_PROVIDER_USAGE_SCENARIO, ULONG, USHORT const*, int*);
    virtual HRESULT STDMETHODCALLTYPE DTR();
};


CCredentialProviderFrameworkWrapper::CCredentialProviderFrameworkWrapper(
    CCredentialProviderFrameworkNew* actualInstance)
{
    m_actualInstance = actualInstance;
    m_cRef = 0;
}

HRESULT CCredentialProviderFrameworkWrapper::QueryInterface(_GUID const& a1, void** a2)
{
    return m_actualInstance->QueryInterface(a1, a2);
}

HRESULT CCredentialProviderFrameworkWrapper::AddRef()
{
    if (m_actualInstance)
        m_actualInstance->AddRef();
    return InterlockedIncrement(&m_cRef);
}

HRESULT CCredentialProviderFrameworkWrapper::Release()
{
    m_actualInstance->Release();
    if (InterlockedDecrement(&m_cRef) == 0)
    {
        free((void*)this);
        return 0;
    }
    return m_cRef;
}

HRESULT CCredentialProviderFrameworkWrapper::InitializeAsync(int a1, void* a2, void* a3, USHORT a4)
{
    return m_actualInstance->InitializeAsync(a1,0,a2,a3,a4);
}
//_CREDENTIAL_PROVIDER_USAGE_SCENARIO, ULONG, void*, _GUID const*, UCHAR const*, UINT, USHORT const*
HRESULT CCredentialProviderFrameworkWrapper::StartCredProvsAsync(int a1, ULONG a2, void* a3, _GUID const* a4, UCHAR const* a5, UINT a6)
{
    return m_actualInstance->StartCredProvsAsync(a1,a2,a3,a4,a5,a6,nullptr);
}

HRESULT CCredentialProviderFrameworkWrapper::AdviseCredProvsAsync()
{
    return m_actualInstance->AdviseCredProvsAsync();
}

HRESULT CCredentialProviderFrameworkWrapper::EnumerateAllCredentialsAsync()
{
    return m_actualInstance->EnumerateAllCredentialsAsync();
}

HRESULT CCredentialProviderFrameworkWrapper::EnumerateTilesForProviderAsync(UINT a1, int a2)
{
    return m_actualInstance->EnumerateTilesForProviderAsync(a1,a2);
}

HRESULT CCredentialProviderFrameworkWrapper::AdviseCredentialAsync(UINT a1, UINT a2, HWND__* a3)
{
    return m_actualInstance->AdviseCredentialAsync(a1,a2,a3);
}

HRESULT CCredentialProviderFrameworkWrapper::SelectCredentialAsync(UINT a1, UINT a2, int a3)
{
    return m_actualInstance->SelectCredentialAsync(a1,a2,a3);
}

HRESULT CCredentialProviderFrameworkWrapper::GetSerializationAsync(UINT a1, UINT a2, void* a3)
{
    return m_actualInstance->GetSerializationAsync(a1,a2,a3);
}

HRESULT CCredentialProviderFrameworkWrapper::GetPicturePasswordSerializationAsync(UINT a1, UINT a2, void* a3, void* a4)
{
    return m_actualInstance->GetPicturePasswordSerializationAsync(a1,a2,a3,a4);
}

HRESULT CCredentialProviderFrameworkWrapper::ReportResultAsync(UINT a1, long a2, long a3, USHORT const* a4)
{
    return m_actualInstance->ReportResultAsync(a1,a2,a3,a4,nullptr,nullptr);
}

HRESULT CCredentialProviderFrameworkWrapper::SetStringDataAsync(UINT a1, UINT a2, ULONG a3, USHORT const* a4)
{
    return m_actualInstance->SetStringDataAsync(a1,a2,a3,a4);
}

HRESULT CCredentialProviderFrameworkWrapper::OnCommandLinkClickedAsync(UINT a1, UINT a2, ULONG a3)
{
    return m_actualInstance->OnCommandLinkClickedAsync(a1,a2,a3);
}

HRESULT CCredentialProviderFrameworkWrapper::SetCheckboxValueAsync(UINT a1, UINT a2, ULONG a3, int a4)
{
    return m_actualInstance->SetCheckboxValueAsync(a1,a2,a3,a4);
}

HRESULT CCredentialProviderFrameworkWrapper::SetComboBoxValueAsync(UINT a1, UINT a2, ULONG a3, ULONG a4)
{
    return m_actualInstance->SetComboBoxValueAsync(a1,a2,a3,a4);
}

HRESULT CCredentialProviderFrameworkWrapper::DisconnectCredentialsAsync()
{
    return m_actualInstance->DisconnectCredentialsAsync();
}

HRESULT CCredentialProviderFrameworkWrapper::BuildUserTileAsync(int a1)
{
    return m_actualInstance->BuildUserTileAsync(a1);
}

HRESULT CCredentialProviderFrameworkWrapper::SetDisplayStateAsync(int a1)
{
    return m_actualInstance->SetDisplayStateAsync(a1);
}

HRESULT CCredentialProviderFrameworkWrapper::UnadviseCredentialAsync(UINT a1, UINT a2)
{
    return m_actualInstance->UnadviseCredentialAsync(a1,a2);
}

HRESULT CCredentialProviderFrameworkWrapper::UnadviseCredProvsAsync()
{
    return m_actualInstance->UnadviseCredProvsAsync();
}

HRESULT CCredentialProviderFrameworkWrapper::Shutdown()
{
    return m_actualInstance->Shutdown();
}

HRESULT CCredentialProviderFrameworkWrapper::CheckProviderAvailability(int a1, ULONG a2, USHORT const* a3, int* a4)
{
    return m_actualInstance->CheckProviderAvailability(a1,a2,a3,a4);
}

HRESULT CCredentialProviderFrameworkWrapper::DTR()
{
    return m_actualInstance->DTR();
}

HRESULT(__stdcall* fCoCreateInstance)(const IID* const rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, const IID* const riid, LPVOID* ppv);
HRESULT __stdcall CoCreateInstance_Hook(const CLSID* const rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, const IID* const riid, LPVOID* ppv)
{
    if ((*rclsid) == GUID_7a872d34_bc6b_4f83_b199_22e9c0a91ddc && (*riid) == GUID_c5874d2e_5a87_48c4_a7d3_6fbb7e8da746)
    {
        CCredentialProviderFrameworkNew* actual = nullptr;
        HRESULT hr = fCoCreateInstance(rclsid,pUnkOuter,dwClsContext,&GUID_2d6268a8_e4ba_4547_84f7_5aab881163b5,(void**)&actual);
        if (FAILED(hr))
            return hr;

        *ppv = new CCredentialProviderFrameworkWrapper(actual);
        return S_OK;
    }

    return fCoCreateInstance(rclsid,pUnkOuter,dwClsContext,riid,ppv);
}

void initHooks()
{
    MH_Initialize();
    
    fCoCreateInstance = (decltype(fCoCreateInstance))GetProcAddress(LoadLibraryW(L"combase.dll"),"CoCreateInstance");
    MH_CreateHook(fCoCreateInstance,CoCreateInstance_Hook,(LPVOID*)(&fCoCreateInstance));
    MH_EnableHook(MH_ALL_HOOKS);
}

HMODULE consoleLogon = 0;

HMODULE GetConsoleLogonDLL()
{
    if (consoleLogon)
        return consoleLogon;

    consoleLogon = LoadLibraryW(L"C:\\Windows\\System32\\CredProvHost.dll");
    if (!consoleLogon)
        MessageBox(0, L"FAILED TO LOAD", L"FAILED TO LOAD", 0);
    return consoleLogon;
}

extern "C" __declspec(dllexport) HRESULT __stdcall DllCanUnloadNow()
{
    //MessageBox(0, L"DllCanUnloadNow", L"DllCanUnloadNow", 0);
    return reinterpret_cast<HRESULT(__stdcall*)()>(GetProcAddress(GetConsoleLogonDLL(), "DllCanUnloadNow"))();
}

extern "C" __declspec(dllexport) HRESULT DllGetActivationFactory(HSTRING string, PVOID Ptr)
{
    //MessageBox(0, L"DllGetActivationFactory", L"DllGetActivationFactory", 0);
    return reinterpret_cast<HRESULT(*)(HSTRING string, PVOID Ptr)>(GetProcAddress(GetConsoleLogonDLL(), "DllGetActivationFactory"))(string, Ptr);
}

extern "C" __declspec(dllexport) HRESULT __stdcall DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)
{
    //MessageBox(0, L"DllGetClassObject", L"DllGetClassObject", 0);
    return reinterpret_cast<HRESULT(__stdcall*)(REFCLSID rclsid, REFIID riid, LPVOID * ppv)>(GetProcAddress(GetConsoleLogonDLL(), "DllGetClassObject"))(rclsid, riid, ppv);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        initHooks();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}