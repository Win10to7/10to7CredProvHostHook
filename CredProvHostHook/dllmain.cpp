// dllmain.cpp : Defines the entry point for the DLL application.
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#define INITGUID
// Windows Header Files
#include <windows.h>
#include <hstring.h>
#include <ntsecapi.h>
#include <new>
#include <stdio.h>

#define DllGetClassObject KYS1
#define DllCanUnloadNow KYS2
#include <objidl.h>
#include <unknwnbase.h>
#undef DllGetClassObject
#undef DllCanUnloadNow

// These private COM interface IDs and layouts were recovered from the 1607 version and
// current (19041.5848) Windows 10 credential-provider binaries. They are not published by the
// Windows SDK, so the adapter must preserve their exact vtable order.
DEFINE_GUID(IID_OldCredProvFramework, 0xC5874D2E, 0x5A87, 0x48C4, 0xA7, 0xD3, 0x6F, 0xBB, 0x7E, 0x8D, 0xA7, 0x46);
DEFINE_GUID(IID_NewCredProvFramework, 0x2D6268A8, 0xE4BA, 0x4547, 0x84, 0xF7, 0x5A, 0xAB, 0x88, 0x11, 0x63, 0xB5);
DEFINE_GUID(IID_CredProvThreadInit, 0x0CCA38EB, 0x78A9, 0x4F49, 0x86, 0x3C, 0x0A, 0xA3, 0x28, 0x88, 0xC1, 0x18);
DEFINE_GUID(IID_CredentialProviderEvents, 0x34201E5A, 0xA787, 0x41A3, 0xA5, 0xA4, 0xBD, 0x6D, 0xCF, 0x2A, 0x85, 0x4E);
DEFINE_GUID(IID_OldCredProvBioEvents, 0x174BDECA, 0x3B44, 0x4A94, 0xA7, 0x85, 0x7C, 0xE2, 0x7F, 0x7F, 0x29, 0x33);
DEFINE_GUID(IID_NewCredProvBioEvents, 0x8AA3EF4E, 0x6A82, 0x467D, 0xA1, 0x59, 0xE0, 0xC9, 0x7D, 0x05, 0x79, 0x52);
DEFINE_GUID(IID_GreetingFormatter, 0x1ABBB96C, 0xB973, 0x43FE, 0x82, 0x0C, 0xDB, 0xCF, 0xD3, 0xA7, 0xCC, 0x7D);
DEFINE_GUID(IID_CredTileData, 0x7B41E003, 0xAA14, 0x46A0, 0x98, 0xB1, 0xBB, 0x99, 0xBF, 0x66, 0x12, 0xD6);
DEFINE_GUID(IID_RequestedCredTileData, 0xE66EBC26, 0x2C31, 0x41A8, 0xBB, 0xF1, 0x04, 0xF5, 0x88, 0xF6, 0x09, 0x76);
DEFINE_GUID(IID_ObjectArray, 0x92CA9DCD, 0x5622, 0x4BBA, 0xA8, 0x05, 0x5E, 0x9F, 0x54, 0x1B, 0xD8, 0xC9);

// The private interfaces use the public credential-provider enum values, but
// their declarations are unavailable in the SDK headers used by this project.
#define CREDENTIAL_SCENARIO int
#define SUPPORTED_UI_FEATURE_FLAGS int
#define _CREDENTIAL_PROVIDER_USAGE_SCENARIO int
#define CREDENTIALSCHANGED_STATE int
#define TILE_SELECTION_FLAGS int
#define _CREDENTIAL_PROVIDER_DISPLAY_STATE_FLAGS int
#define CREDENTIAL_PROVIDER_FEEDBACK_VISUAL_STATE int
#define BIO_FEEDBACK_PRIORITY int
#define GREETING_TYPE int

namespace
{
    struct GreetingParameters;

    // The adapter deliberately keeps CredProvHost.dll loaded for the lifetime
    // of the proxy. Objects created by its class factory retain code pointers
    // into that module.
    HMODULE g_credProvHost = nullptr;
    // One-shot failure reporting avoids stacking system-modal dialogs when an
    // asynchronous failure causes several framework calls to fail together.
    LONG g_errorShown = 0;
    // A failure permanently enables pass-through mode for future activations.
    // Delete this key to re-enable the compatibility adapters.
    constexpr wchar_t BypassRegistryPath[] = L"SOFTWARE\\CredProvHostHook";
    constexpr wchar_t BypassRegistryValue[] = L"BypassAdapters";
    LONG g_bypassAdapters = 0;
    // The remaining globals are watchdog telemetry. They record which side of
    // the recovered ABI boundary was reached when the UI stops making progress.
    LONG g_frameworkCalls = 0;
    INIT_ONCE g_authPackageInit = INIT_ONCE_STATIC_INIT;
    ULONG g_authPackages[2] = {};
    UINT g_authPackageCount = 0;
    LONG g_tileArrayCount = -1;
    LONG g_firstProviderId = -1;
    LONG g_firstCredentialId = -1;
    LONG g_firstFieldCount = -1;
    LONG g_firstTileVisible = -1;
    LONG g_firstCredentialMethod = -1;
    LONG g_validatedFieldCount = 0;
    LONG g_consumerArrayCountCalls = 0;
    LONG g_consumerArrayGetAtCalls = 0;
    LONG g_consumerTileMethodMask = 0;
    LONG g_consumerTileLastMethod = -1;
    GUID g_consumerGetAtIid = {};
    LONG g_consumerGetAtIidSet = 0;
    GUID g_consumerTileQueryIid = {};
    LONG g_consumerTileQueryIidSet = 0;
    LONG g_consumerTileQueryCalls = 0;
    LONG g_consumerGetAtResult = E_PENDING;
    LONG g_legacyTileConversions = 0;

    // Format private interface IDs without relying on COM helper libraries.
    void FormatGuid(const GUID& guid, wchar_t* text, size_t textCount)
    {
        swprintf_s(
            text,
            textCount,
            L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            guid.Data1,
            guid.Data2,
            guid.Data3,
            guid.Data4[0],
            guid.Data4[1],
            guid.Data4[2],
            guid.Data4[3],
            guid.Data4[4],
            guid.Data4[5],
            guid.Data4[6],
            guid.Data4[7]);
    }

    HRESULT PersistBypassMode()
    {
        InterlockedExchange(&g_bypassAdapters, 1);

        HKEY key = nullptr;
        const LSTATUS createStatus = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            BypassRegistryPath,
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            nullptr,
            &key,
            nullptr);
        if (createStatus != ERROR_SUCCESS)
        {
            return HRESULT_FROM_WIN32(createStatus);
        }

        const DWORD enabled = 1;
        const LSTATUS setStatus = RegSetValueExW(
            key,
            BypassRegistryValue,
            0,
            REG_DWORD,
            reinterpret_cast<const BYTE*>(&enabled),
            sizeof(enabled));
        RegCloseKey(key);
        return HRESULT_FROM_WIN32(setStatus);
    }

    bool IsBypassModeEnabled()
    {
        if (InterlockedCompareExchange(&g_bypassAdapters, 0, 0) != 0)
        {
            return true;
        }

        HKEY key = nullptr;
        const LSTATUS openStatus = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            BypassRegistryPath,
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &key);
        if (openStatus != ERROR_SUCCESS)
        {
            return false;
        }

        DWORD enabled = 0;
        DWORD type = 0;
        DWORD size = sizeof(enabled);
        const LSTATUS queryStatus = RegQueryValueExW(
            key,
            BypassRegistryValue,
            nullptr,
            &type,
            reinterpret_cast<BYTE*>(&enabled),
            &size);
        RegCloseKey(key);

        if (queryStatus != ERROR_SUCCESS || type != REG_DWORD ||
            size != sizeof(enabled) || enabled == 0)
        {
            return false;
        }

        InterlockedExchange(&g_bypassAdapters, 1);
        return true;
    }

    // Surface private-framework failures in the secure/UAC desktop, where no
    // console or ordinary debugger output is normally visible.
    HRESULT ReportFailure(const wchar_t* stage, HRESULT result)
    {
        if (SUCCEEDED(result) || InterlockedCompareExchange(&g_errorShown, 1, 0) != 0)
        {
            return result;
        }

        const HRESULT bypassResult = PersistBypassMode();

        wchar_t systemMessage[512] = {};
        FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            static_cast<DWORD>(result),
            0,
            systemMessage,
            ARRAYSIZE(systemMessage),
            nullptr);

        wchar_t message[1536] = {};
        swprintf_s(
            message,
            L"CredProvHostHook could not display the credential prompt.\n\n"
            L"Stage: %s\nHRESULT: 0x%08X\n%s"
            L"\n\n%s\nFail-safe HRESULT: 0x%08X",
            stage,
            static_cast<unsigned int>(result),
            systemMessage,
            SUCCEEDED(bypassResult)
                ? L"CredProvHostHook has been disabled. On the next credential-host activation, all calls will be forwarded directly to CredProvHost.dll. Please report the full error on GitHub."
                : L"CredProvHostHook could not enable its persistent fail-safe. The hook has only been disabled for the current process. Please report the full error on GitHub.",
            static_cast<unsigned int>(bypassResult));

        MessageBoxW(
            nullptr,
            message,
            L"CredProvHostHook error",
            MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_SETFOREGROUND | MB_SERVICE_NOTIFICATION);
        return result;
    }
    // Each prompt transition changes this generation. A watchdog reports only
    // if the same generation remains active for the full timeout.
    LONG g_promptGeneration = 0;

    DWORD WINAPI PromptWatchdogThread(void* parameter)
    {
        const LONG generation = static_cast<LONG>(PtrToUlong(parameter));
        Sleep(15000);
        if (InterlockedCompareExchange(&g_promptGeneration, 0, 0) == generation)
        {
            wchar_t getAtIid[40] = L"none";
            wchar_t tileQueryIid[40] = L"none";
            if (InterlockedCompareExchange(&g_consumerGetAtIidSet, 0, 0) != 0)
            {
                FormatGuid(g_consumerGetAtIid, getAtIid, ARRAYSIZE(getAtIid));
            }
            if (InterlockedCompareExchange(&g_consumerTileQueryIidSet, 0, 0) != 0)
            {
                FormatGuid(g_consumerTileQueryIid, tileQueryIid, ARRAYSIZE(tileQueryIid));
            }
            wchar_t stage[512] = {};
            swprintf_s(
                stage,
                L"Prompt timeout after validating credential conversion; framework=%08X authPackages=%u "
                L"tiles=%d provider=%d credential=%d fields=%d validatedFields=%d visible=%d method=%08X "
                L"arrayReads=%d/%d getAtIid=%s getAtResult=%08X conversions=%d tileQI=%d/%s "
                L"tileMethods=%08X lastTileMethod=%d",
                static_cast<unsigned int>(InterlockedCompareExchange(&g_frameworkCalls, 0, 0)),
                g_authPackageCount,
                InterlockedCompareExchange(&g_tileArrayCount, 0, 0),
                InterlockedCompareExchange(&g_firstProviderId, 0, 0),
                InterlockedCompareExchange(&g_firstCredentialId, 0, 0),
                InterlockedCompareExchange(&g_firstFieldCount, 0, 0),
                InterlockedCompareExchange(&g_validatedFieldCount, 0, 0),
                InterlockedCompareExchange(&g_firstTileVisible, 0, 0),
                static_cast<unsigned int>(InterlockedCompareExchange(&g_firstCredentialMethod, 0, 0)),
                InterlockedCompareExchange(&g_consumerArrayCountCalls, 0, 0),
                InterlockedCompareExchange(&g_consumerArrayGetAtCalls, 0, 0),
                getAtIid,
                static_cast<unsigned int>(InterlockedCompareExchange(&g_consumerGetAtResult, 0, 0)),
                InterlockedCompareExchange(&g_legacyTileConversions, 0, 0),
                InterlockedCompareExchange(&g_consumerTileQueryCalls, 0, 0),
                tileQueryIid,
                static_cast<unsigned int>(InterlockedCompareExchange(&g_consumerTileMethodMask, 0, 0)),
                InterlockedCompareExchange(&g_consumerTileLastMethod, 0, 0));
            ReportFailure(stage, HRESULT_FROM_WIN32(WAIT_TIMEOUT));
        }
        return 0;
    }

    // Pin this DLL before creating the detached watchdog thread so its entry
    // point cannot be unloaded while the thread is sleeping.
    void ArmPromptWatchdog()
    {
        HMODULE module = nullptr;
        if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            reinterpret_cast<LPCWSTR>(&PromptWatchdogThread),
            &module))
        {
            ReportFailure(L"Pin prompt watchdog module", HRESULT_FROM_WIN32(GetLastError()));
            return;
        }

        const LONG generation = InterlockedIncrement(&g_promptGeneration);
        HANDLE thread = CreateThread(
            nullptr,
            0,
            PromptWatchdogThread,
            ULongToPtr(static_cast<ULONG>(generation)),
            0,
            nullptr);
        if (!thread)
        {
            ReportFailure(L"Start prompt watchdog", HRESULT_FROM_WIN32(GetLastError()));
            return;
        }
        CloseHandle(thread);
    }

    void MarkPromptUiActive()
    {
        InterlockedIncrement(&g_promptGeneration);
    }

    // Old consumers can start the framework without an authentication-package
    // context. The current host requires the actual LSA package IDs, which vary
    // by installation and therefore must be queried instead of hard-coded.
    BOOL CALLBACK InitializeAuthPackages(PINIT_ONCE, PVOID, PVOID*)
    {
        using LsaConnectUntrustedFn = NTSTATUS (NTAPI*)(PHANDLE);
        using LsaLookupAuthenticationPackageFn = NTSTATUS (NTAPI*)(HANDLE, PLSA_STRING, PULONG);
        using LsaDeregisterLogonProcessFn = NTSTATUS (NTAPI*)(HANDLE);

        HMODULE secur32 = LoadLibraryW(L"secur32.dll");
        if (!secur32)
        {
            return TRUE;
        }

        const auto connect = reinterpret_cast<LsaConnectUntrustedFn>(
            GetProcAddress(secur32, "LsaConnectUntrusted"));
        const auto lookup = reinterpret_cast<LsaLookupAuthenticationPackageFn>(
            GetProcAddress(secur32, "LsaLookupAuthenticationPackage"));
        const auto disconnect = reinterpret_cast<LsaDeregisterLogonProcessFn>(
            GetProcAddress(secur32, "LsaDeregisterLogonProcess"));

        HANDLE lsa = nullptr;
        if (connect && lookup && disconnect && connect(&lsa) == 0)
        {
            char negotiateBuffer[] = "Negotiate";
            LSA_STRING negotiate = {};
            negotiate.Buffer = negotiateBuffer;
            negotiate.Length = static_cast<USHORT>(sizeof(negotiateBuffer) - 1);
            negotiate.MaximumLength = static_cast<USHORT>(sizeof(negotiateBuffer));
            if (lookup(lsa, &negotiate, &g_authPackages[g_authPackageCount]) == 0)
            {
                ++g_authPackageCount;
            }

            char ntlmBuffer[] = "NTLM";
            LSA_STRING ntlm = {};
            ntlm.Buffer = ntlmBuffer;
            ntlm.Length = static_cast<USHORT>(sizeof(ntlmBuffer) - 1);
            ntlm.MaximumLength = static_cast<USHORT>(sizeof(ntlmBuffer));
            if (g_authPackageCount < ARRAYSIZE(g_authPackages)
                && lookup(lsa, &ntlm, &g_authPackages[g_authPackageCount]) == 0)
            {
                ++g_authPackageCount;
            }
            disconnect(lsa);
        }

        FreeLibrary(secur32);
        return TRUE;
    }

    // Expose the package-ID array in the byte-oriented form used by the private
    // StartCredProvsAsync contract.
    bool GetLegacyAuthPackageContext(const UCHAR** contextBytes, UINT* contextCount)
    {
        if (!InitOnceExecuteOnce(&g_authPackageInit, InitializeAuthPackages, nullptr, nullptr)
            || g_authPackageCount == 0)
        {
            return false;
        }

        *contextBytes = reinterpret_cast<const UCHAR*>(g_authPackages);
        *contextCount = g_authPackageCount;
        return true;
    }

    // Validate the new framework's tile graph before handing it to an older UI.
    // This turns otherwise silent asynchronous ABI failures into a precise
    // stage and also captures enough metadata for the prompt watchdog.
    HRESULT ValidateTileArray(void* array)
    {
        if (!array)
        {
            return ReportFailure(L"New framework returned a null tile array", E_POINTER);
        }

        auto** vtable = reinterpret_cast<void***>(array);
        using GetCount = HRESULT (STDMETHODCALLTYPE*)(void*, UINT*);
        using GetAt = HRESULT (STDMETHODCALLTYPE*)(void*, UINT, REFIID, void**);

        UINT count = 0;
        HRESULT result = reinterpret_cast<GetCount>((*vtable)[3])(array, &count);
        if (FAILED(result))
        {
            return ReportFailure(L"Read returned tile-array count", result);
        }
        InterlockedExchange(&g_tileArrayCount, static_cast<LONG>(count));

        for (UINT index = 0; index < count; ++index)
        {
            void* tile = nullptr;
            result = reinterpret_cast<GetAt>((*vtable)[4])(array, index, IID_CredTileData, &tile);
            if (FAILED(result))
            {
                wchar_t stage[128] = {};
                swprintf_s(stage, L"Get ICredTileData for returned tile %u", index);
                return ReportFailure(stage, result);
            }

            auto** tileVtable = reinterpret_cast<void***>(tile);
            using GetValue = UINT (STDMETHODCALLTYPE*)(void*);
            using GetFieldAt = HRESULT (STDMETHODCALLTYPE*)(void*, UINT, void**);
            using GetCredentialMethod = HRESULT (STDMETHODCALLTYPE*)(void*, UINT*);

            const UINT fieldCount = reinterpret_cast<GetValue>((*tileVtable)[5])(tile);
            if (index == 0)
            {
                InterlockedExchange(
                    &g_firstProviderId,
                    static_cast<LONG>(reinterpret_cast<GetValue>((*tileVtable)[3])(tile)));
                InterlockedExchange(
                    &g_firstCredentialId,
                    static_cast<LONG>(reinterpret_cast<GetValue>((*tileVtable)[4])(tile)));
                InterlockedExchange(&g_firstFieldCount, static_cast<LONG>(fieldCount));
                InterlockedExchange(
                    &g_firstTileVisible,
                    static_cast<LONG>(reinterpret_cast<GetValue>((*tileVtable)[14])(tile)));

                UINT credentialMethod = 0;
                result = reinterpret_cast<GetCredentialMethod>((*tileVtable)[22])(tile, &credentialMethod);
                if (FAILED(result))
                {
                    reinterpret_cast<IUnknown*>(tile)->Release();
                    return ReportFailure(L"Read credential method from returned tile", result);
                }
                InterlockedExchange(&g_firstCredentialMethod, static_cast<LONG>(credentialMethod));
            }

            for (UINT fieldIndex = 0; fieldIndex < fieldCount; ++fieldIndex)
            {
                void* field = nullptr;
                result = reinterpret_cast<GetFieldAt>((*tileVtable)[6])(tile, fieldIndex, &field);
                if (FAILED(result))
                {
                    wchar_t stage[128] = {};
                    swprintf_s(stage, L"Read field %u from returned tile %u", fieldIndex, index);
                    reinterpret_cast<IUnknown*>(tile)->Release();
                    return ReportFailure(stage, result);
                }
                if (!field)
                {
                    reinterpret_cast<IUnknown*>(tile)->Release();
                    return ReportFailure(L"New framework returned a null field object", E_POINTER);
                }

                auto** fieldVtable = reinterpret_cast<void***>(field);
                reinterpret_cast<GetValue>((*fieldVtable)[4])(field);
                reinterpret_cast<GetValue>((*fieldVtable)[5])(field);
                reinterpret_cast<IUnknown*>(field)->Release();
                InterlockedIncrement(&g_validatedFieldCount);
            }

            reinterpret_cast<IUnknown*>(tile)->Release();
        }
        return S_OK;
    }

    // Generic slot declarations are intentional: most private tile methods are
    // only forwarded, and their published C++ signatures are unavailable.
    class ITracingCredTile : public IUnknown
    {
    public:
#define TILE_METHOD(slot) virtual ULONG_PTR STDMETHODCALLTYPE Method##slot(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR) = 0
        TILE_METHOD(3);
        TILE_METHOD(4);
        TILE_METHOD(5);
        TILE_METHOD(6);
        TILE_METHOD(7);
        TILE_METHOD(8);
        TILE_METHOD(9);
        TILE_METHOD(10);
        TILE_METHOD(11);
        TILE_METHOD(12);
        TILE_METHOD(13);
        TILE_METHOD(14);
        TILE_METHOD(15);
        TILE_METHOD(16);
        TILE_METHOD(17);
        TILE_METHOD(18);
        TILE_METHOD(19);
        TILE_METHOD(20);
        TILE_METHOD(21);
        TILE_METHOD(22);
        TILE_METHOD(23);
        TILE_METHOD(24);
        TILE_METHOD(25);
        TILE_METHOD(26);
        TILE_METHOD(27);
        TILE_METHOD(28);
        TILE_METHOD(29);
        TILE_METHOD(30);
#undef TILE_METHOD
    };

    // Wrap each tile so the consumer sees the IID and vtable layout it asked
    // for while the underlying object remains owned by the current framework.
    class CTracingCredTile final : public ITracingCredTile
    {
    public:
        CTracingCredTile(IUnknown* tile, bool legacyContract)
            : m_tile(tile), m_legacyContract(legacyContract)
        {
            m_tile->AddRef();
        }

        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** object) override
        {
            if (!object)
            {
                return E_POINTER;
            }
            g_consumerTileQueryIid = riid;
            InterlockedExchange(&g_consumerTileQueryIidSet, 1);
            InterlockedIncrement(&g_consumerTileQueryCalls);
            *object = nullptr;
            if (riid == IID_IUnknown ||
                (!m_legacyContract && riid == IID_CredTileData) ||
                (m_legacyContract && riid == IID_RequestedCredTileData))
            {
                *object = static_cast<ITracingCredTile*>(this);
                AddRef();
                return S_OK;
            }
            return m_tile->QueryInterface(riid, object);
        }

        ULONG STDMETHODCALLTYPE AddRef() override
        {
            return static_cast<ULONG>(InterlockedIncrement(&m_refCount));
        }

        ULONG STDMETHODCALLTYPE Release() override
        {
            const ULONG count = static_cast<ULONG>(InterlockedDecrement(&m_refCount));
            if (count == 0)
            {
                delete this;
            }
            return count;
        }

    // The current tile interface inserted IsTileVisible at slot 14. For the
    // legacy IID, old slots 14-20 therefore map to current slots 15-21.
#define FORWARD_TILE_METHOD(slot) \
        ULONG_PTR STDMETHODCALLTYPE Method##slot(ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3, ULONG_PTR a4, ULONG_PTR a5, ULONG_PTR a6, ULONG_PTR a7, ULONG_PTR a8) override \
        { \
            InterlockedOr(&g_consumerTileMethodMask, 1L << slot); \
            InterlockedExchange(&g_consumerTileLastMethod, slot); \
            using Method = ULONG_PTR (STDMETHODCALLTYPE*)(IUnknown*, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR); \
            const UINT sourceSlot = m_legacyContract && slot >= 14 && slot <= 20 ? slot + 1 : slot; \
            auto** vtable = reinterpret_cast<void***>(m_tile); \
            return reinterpret_cast<Method>((*vtable)[sourceSlot])(m_tile, a1, a2, a3, a4, a5, a6, a7, a8); \
        }
        FORWARD_TILE_METHOD(3)
        FORWARD_TILE_METHOD(4)
        FORWARD_TILE_METHOD(5)
        FORWARD_TILE_METHOD(6)
        FORWARD_TILE_METHOD(7)
        FORWARD_TILE_METHOD(8)
        FORWARD_TILE_METHOD(9)
        FORWARD_TILE_METHOD(10)
        FORWARD_TILE_METHOD(11)
        FORWARD_TILE_METHOD(12)
        FORWARD_TILE_METHOD(13)
        FORWARD_TILE_METHOD(14)
        FORWARD_TILE_METHOD(15)
        FORWARD_TILE_METHOD(16)
        FORWARD_TILE_METHOD(17)
        FORWARD_TILE_METHOD(18)
        FORWARD_TILE_METHOD(19)
        FORWARD_TILE_METHOD(20)
        FORWARD_TILE_METHOD(21)
        FORWARD_TILE_METHOD(22)
        FORWARD_TILE_METHOD(23)
        FORWARD_TILE_METHOD(24)
        FORWARD_TILE_METHOD(25)
        FORWARD_TILE_METHOD(26)
        FORWARD_TILE_METHOD(27)
        FORWARD_TILE_METHOD(28)
        FORWARD_TILE_METHOD(29)
        FORWARD_TILE_METHOD(30)
#undef FORWARD_TILE_METHOD

    private:
        ~CTracingCredTile()
        {
            m_tile->Release();
        }

        IUnknown* m_tile;
        bool m_legacyContract;
        LONG m_refCount = 1;
    };

    // The asynchronous callback supplies a new IObjectArray. This proxy changes
    // a request for the legacy tile IID into the current IID, then wraps the
    // returned tile with the legacy slot mapping above.
    class CTracingObjectArray final : public IUnknown
    {
    public:
        explicit CTracingObjectArray(IUnknown* array)
            : m_array(array)
        {
            m_array->AddRef();
        }

        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** object) override
        {
            if (!object)
            {
                return E_POINTER;
            }
            *object = nullptr;
            if (riid == IID_IUnknown || riid == IID_ObjectArray)
            {
                *object = static_cast<IUnknown*>(this);
                AddRef();
                return S_OK;
            }
            return m_array->QueryInterface(riid, object);
        }

        ULONG STDMETHODCALLTYPE AddRef() override
        {
            return static_cast<ULONG>(InterlockedIncrement(&m_refCount));
        }

        ULONG STDMETHODCALLTYPE Release() override
        {
            const ULONG count = static_cast<ULONG>(InterlockedDecrement(&m_refCount));
            if (count == 0)
            {
                delete this;
            }
            return count;
        }

        virtual HRESULT STDMETHODCALLTYPE GetCount(UINT* count)
        {
            InterlockedIncrement(&g_consumerArrayCountCalls);
            using Method = HRESULT (STDMETHODCALLTYPE*)(IUnknown*, UINT*);
            auto** vtable = reinterpret_cast<void***>(m_array);
            return reinterpret_cast<Method>((*vtable)[3])(m_array, count);
        }

        virtual HRESULT STDMETHODCALLTYPE GetAt(UINT index, REFIID riid, void** object)
        {
            InterlockedIncrement(&g_consumerArrayGetAtCalls);
            g_consumerGetAtIid = riid;
            InterlockedExchange(&g_consumerGetAtIidSet, 1);
            if (!object)
            {
                InterlockedExchange(&g_consumerGetAtResult, E_POINTER);
                return E_POINTER;
            }
            *object = nullptr;

            // The current array cannot answer the legacy IID directly. Request
            // its native tile interface first and expose the requested contract
            // only after a real tile object has been returned successfully.
            const bool legacyRequest = riid == IID_RequestedCredTileData;
            const GUID& sourceIid = legacyRequest ? IID_CredTileData : riid;
            using Method = HRESULT (STDMETHODCALLTYPE*)(IUnknown*, UINT, REFIID, void**);
            auto** vtable = reinterpret_cast<void***>(m_array);
            const HRESULT result = reinterpret_cast<Method>((*vtable)[4])(
                m_array, index, sourceIid, object);
            InterlockedExchange(&g_consumerGetAtResult, result);
            if (FAILED(result) ||
                (riid != IID_CredTileData && !legacyRequest) ||
                !*object)
            {
                return result;
            }

            auto* originalTile = reinterpret_cast<IUnknown*>(*object);
            auto* tracedTile = new (std::nothrow) CTracingCredTile(originalTile, legacyRequest);
            originalTile->Release();
            if (!tracedTile)
            {
                *object = nullptr;
                return E_OUTOFMEMORY;
            }
            if (legacyRequest)
            {
                InterlockedIncrement(&g_legacyTileConversions);
            }
            *object = static_cast<ITracingCredTile*>(tracedTile);
            return S_OK;
        }

    private:
        ~CTracingObjectArray()
        {
            m_array->Release();
        }

        IUnknown* m_array;
        LONG m_refCount = 1;
    };

    // AuthUI from 1607 (AuthUAC in NTMU's Legacy UAC pack and 21H2to7 Legacy UAC) uses the intermediate serialization interface: it added
    // GetProviderClsid, but still expects GetSerialization in vtable slot 5.
    // The current CredProvHost.dll interface inserts GetSerializationFlags,
    // moving GetSerialization to slot 6.
    class IConsumerCredentialSerialization : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE GetAuthenticationPackage(ULONG* authenticationPackage) = 0;
        virtual HRESULT STDMETHODCALLTYPE GetProviderClsid(GUID* providerClsid) = 0;
        virtual HRESULT STDMETHODCALLTYPE GetSerialization(ULONG* byteCount, BYTE** bytes) = 0;
    };

    class CConsumerCredentialSerialization final : public IConsumerCredentialSerialization
    {
    public:
        explicit CConsumerCredentialSerialization(IUnknown* serialization)
            : m_serialization(serialization)
        {
            m_serialization->AddRef();
        }

        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** object) override
        {
            if (!object)
            {
                return E_POINTER;
            }
            if (riid == IID_IUnknown)
            {
                *object = static_cast<IConsumerCredentialSerialization*>(this);
                AddRef();
                return S_OK;
            }
            return m_serialization->QueryInterface(riid, object);
        }

        ULONG STDMETHODCALLTYPE AddRef() override
        {
            return static_cast<ULONG>(InterlockedIncrement(&m_refCount));
        }

        ULONG STDMETHODCALLTYPE Release() override
        {
            const ULONG count = static_cast<ULONG>(InterlockedDecrement(&m_refCount));
            if (count == 0)
            {
                delete this;
            }
            return count;
        }

        // Slots 3 and 4 are unchanged between the consumer and current host.
        HRESULT STDMETHODCALLTYPE GetAuthenticationPackage(ULONG* authenticationPackage) override
        {
            using Method = HRESULT (STDMETHODCALLTYPE*)(IUnknown*, ULONG*);
            auto** vtable = reinterpret_cast<void***>(m_serialization);
            return ReportFailure(
                L"Read authentication package from converted serialization",
                reinterpret_cast<Method>((*vtable)[3])(m_serialization, authenticationPackage));
        }

        HRESULT STDMETHODCALLTYPE GetProviderClsid(GUID* providerClsid) override
        {
            using Method = HRESULT (STDMETHODCALLTYPE*)(IUnknown*, GUID*);
            auto** vtable = reinterpret_cast<void***>(m_serialization);
            return ReportFailure(
                L"Read provider CLSID from converted serialization",
                reinterpret_cast<Method>((*vtable)[4])(m_serialization, providerClsid));
        }

        // Translate consumer slot 5 to current CredProvHost.dll slot 6.
        HRESULT STDMETHODCALLTYPE GetSerialization(ULONG* byteCount, BYTE** bytes) override
        {
            using Method = HRESULT (STDMETHODCALLTYPE*)(IUnknown*, ULONG*, BYTE**);
            auto** vtable = reinterpret_cast<void***>(m_serialization);
            return ReportFailure(
                L"Read converted credential serialization",
                reinterpret_cast<Method>((*vtable)[6])(m_serialization, byteCount, bytes));
        }

    private:
        ~CConsumerCredentialSerialization()
        {
            m_serialization->Release();
        }

        IUnknown* m_serialization;
        LONG m_refCount = 1;
    };

    // Callback slot order is shared by the recovered framework versions. Slots
    // 5 and 11 carry objects whose nested interfaces changed and need adapters;
    // all other callbacks can be forwarded without translating their payloads.
    class ICredProvFrameworkCallbackCompat : public IUnknown
    {
    public:
#define CALLBACK_METHOD(slot) virtual HRESULT STDMETHODCALLTYPE Method##slot(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR) = 0
        CALLBACK_METHOD(3);
        CALLBACK_METHOD(4);
        CALLBACK_METHOD(5);
        CALLBACK_METHOD(6);
        CALLBACK_METHOD(7);
        CALLBACK_METHOD(8);
        CALLBACK_METHOD(9);
        CALLBACK_METHOD(10);
        CALLBACK_METHOD(11);
        CALLBACK_METHOD(12);
        CALLBACK_METHOD(13);
        CALLBACK_METHOD(14);
        CALLBACK_METHOD(15);
        CALLBACK_METHOD(16);
        CALLBACK_METHOD(17);
        CALLBACK_METHOD(18);
        CALLBACK_METHOD(19);
        CALLBACK_METHOD(20);
        CALLBACK_METHOD(21);
        CALLBACK_METHOD(22);
        CALLBACK_METHOD(23);
        CALLBACK_METHOD(24);
#undef CALLBACK_METHOD
    };

    class CCredProvFrameworkCallbackValidator final : public ICredProvFrameworkCallbackCompat
    {
    public:
        explicit CCredProvFrameworkCallbackValidator(IUnknown* callback)
            : m_callback(callback)
        {
            m_callback->AddRef();
        }

        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** object) override
        {
            if (!object)
            {
                return E_POINTER;
            }
            if (riid == IID_IUnknown)
            {
                *object = static_cast<ICredProvFrameworkCallbackCompat*>(this);
                AddRef();
                return S_OK;
            }
            return m_callback->QueryInterface(riid, object);
        }

        ULONG STDMETHODCALLTYPE AddRef() override
        {
            return static_cast<ULONG>(InterlockedIncrement(&m_refCount));
        }

        ULONG STDMETHODCALLTYPE Release() override
        {
            const ULONG count = static_cast<ULONG>(InterlockedDecrement(&m_refCount));
            if (count == 0)
            {
                delete this;
            }
            return count;
        }

#define FORWARD_CALLBACK(slot) \
        HRESULT STDMETHODCALLTYPE Method##slot(ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3, ULONG_PTR a4, ULONG_PTR a5, ULONG_PTR a6, ULONG_PTR a7, ULONG_PTR a8) override \
        { \
            using Method = HRESULT (STDMETHODCALLTYPE*)(IUnknown*, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR); \
            auto** vtable = reinterpret_cast<void***>(m_callback); \
            return reinterpret_cast<Method>((*vtable)[slot])(m_callback, a1, a2, a3, a4, a5, a6, a7, a8); \
        }
        FORWARD_CALLBACK(3)
        FORWARD_CALLBACK(4)
        // Slot 5 is OnTilesEnumeratedForProvider. Validate the native payload,
        // then keep the array proxy alive across the consumer's async dispatch.
        HRESULT STDMETHODCALLTYPE Method5(ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3, ULONG_PTR a4, ULONG_PTR a5, ULONG_PTR a6, ULONG_PTR a7, ULONG_PTR a8) override
        {
            const HRESULT validationResult = ValidateTileArray(reinterpret_cast<void*>(a2));
            if (FAILED(validationResult))
            {
                return validationResult;
            }
            auto* tracedArray = new (std::nothrow) CTracingObjectArray(reinterpret_cast<IUnknown*>(a2));
            if (!tracedArray)
            {
                return ReportFailure(L"Allocate asynchronous tile-array tracer", E_OUTOFMEMORY);
            }
            using Method = HRESULT (STDMETHODCALLTYPE*)(IUnknown*, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
            auto** vtable = reinterpret_cast<void***>(m_callback);
            const HRESULT result = reinterpret_cast<Method>((*vtable)[5])(
                m_callback, a1, reinterpret_cast<ULONG_PTR>(tracedArray), a3, a4, a5, a6, a7, a8);
            tracedArray->Release();
            return result;
        }
        FORWARD_CALLBACK(6)
        FORWARD_CALLBACK(7)
        FORWARD_CALLBACK(8)
        FORWARD_CALLBACK(9)
        FORWARD_CALLBACK(10)
        // Slot 11 is OnSerializationComplete. Null serialization is valid for
        // non-success responses and must be forwarded unchanged.
        HRESULT STDMETHODCALLTYPE Method11(ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3, ULONG_PTR a4, ULONG_PTR a5, ULONG_PTR a6, ULONG_PTR a7, ULONG_PTR a8) override
        {
            using Method = HRESULT (STDMETHODCALLTYPE*)(IUnknown*, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
            auto** vtable = reinterpret_cast<void***>(m_callback);
            if (!a4)
            {
                return reinterpret_cast<Method>((*vtable)[11])(m_callback, a1, a2, a3, a4, a5, a6, a7, a8);
            }

            // The callback is dispatched asynchronously. The consumer takes
            // its own reference before posting, so releasing our reference
            // after the callback returns preserves the adapter's lifetime.
            auto* serialization = new (std::nothrow) CConsumerCredentialSerialization(
                reinterpret_cast<IUnknown*>(a4));
            if (!serialization)
            {
                return ReportFailure(L"Allocate credential serialization adapter", E_OUTOFMEMORY);
            }
            const HRESULT result = reinterpret_cast<Method>((*vtable)[11])(
                m_callback,
                a1,
                a2,
                a3,
                reinterpret_cast<ULONG_PTR>(serialization),
                a5,
                a6,
                a7,
                a8);
            serialization->Release();
            return result;
        }
        FORWARD_CALLBACK(12)
        FORWARD_CALLBACK(13)
        FORWARD_CALLBACK(14)
        FORWARD_CALLBACK(15)
        FORWARD_CALLBACK(16)
        FORWARD_CALLBACK(17)
        FORWARD_CALLBACK(18)
        FORWARD_CALLBACK(19)
        FORWARD_CALLBACK(20)
        FORWARD_CALLBACK(21)
        FORWARD_CALLBACK(22)
        FORWARD_CALLBACK(23)
        FORWARD_CALLBACK(24)
#undef FORWARD_CALLBACK

    private:
        ~CCredProvFrameworkCallbackValidator()
        {
            m_callback->Release();
        }

        IUnknown* m_callback;
        LONG m_refCount = 1;
    };


    // Current root interface. Relative to the old contract it adds supported
    // UI features to InitializeAsync, a user suggestion to StartCredProvsAsync,
    // extra ReportResultAsync strings, and two methods at the vtable tail.
    class INewCredProvFramework : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE InitializeAsync(CREDENTIAL_SCENARIO scenario, SUPPORTED_UI_FEATURE_FLAGS supportedUiFeatures, void* autoLogonManager, void* callback, USHORT reserved) = 0;
        virtual HRESULT STDMETHODCALLTYPE StartCredProvsAsync(_CREDENTIAL_PROVIDER_USAGE_SCENARIO usageScenario, ULONG flags, void* serialization, const GUID* providerFilter, const UCHAR* contextBytes, UINT contextByteCount, const USHORT* userSuggestion) = 0;
        virtual HRESULT STDMETHODCALLTYPE AdviseCredProvsAsync() = 0;
        virtual HRESULT STDMETHODCALLTYPE EnumerateAllCredentialsAsync() = 0;
        virtual HRESULT STDMETHODCALLTYPE EnumerateTilesForProviderAsync(UINT providerIndex, CREDENTIALSCHANGED_STATE state) = 0;
        virtual HRESULT STDMETHODCALLTYPE AdviseCredentialAsync(UINT providerIndex, UINT credentialIndex, HWND__* hwnd) = 0;
        virtual HRESULT STDMETHODCALLTYPE SelectCredentialAsync(UINT providerIndex, UINT credentialIndex, TILE_SELECTION_FLAGS flags) = 0;
        virtual HRESULT STDMETHODCALLTYPE GetSerializationAsync(UINT providerIndex, UINT credentialIndex, void* status) = 0;
        virtual HRESULT STDMETHODCALLTYPE GetPicturePasswordSerializationAsync(UINT providerIndex, UINT credentialIndex, void* status, void* inspectable) = 0;
        virtual HRESULT STDMETHODCALLTYPE ReportResultAsync(UINT providerIndex, long ntstatus, long substatus, const USHORT* statusText, const USHORT* statusIconText, const USHORT* statusTooltipText) = 0;
        virtual HRESULT STDMETHODCALLTYPE SetStringDataAsync(UINT providerIndex, UINT credentialIndex, ULONG fieldId, const USHORT* value) = 0;
        virtual HRESULT STDMETHODCALLTYPE OnCommandLinkClickedAsync(UINT providerIndex, UINT credentialIndex, ULONG fieldId) = 0;
        virtual HRESULT STDMETHODCALLTYPE SetCheckboxValueAsync(UINT providerIndex, UINT credentialIndex, ULONG fieldId, int checkedValue) = 0;
        virtual HRESULT STDMETHODCALLTYPE SetComboBoxValueAsync(UINT providerIndex, UINT credentialIndex, ULONG fieldId, ULONG selectedItem) = 0;
        virtual HRESULT STDMETHODCALLTYPE DisconnectCredentialsAsync() = 0;
        virtual HRESULT STDMETHODCALLTYPE BuildUserTileAsync(_CREDENTIAL_PROVIDER_USAGE_SCENARIO usageScenario) = 0;
        virtual HRESULT STDMETHODCALLTYPE SetDisplayStateAsync(_CREDENTIAL_PROVIDER_DISPLAY_STATE_FLAGS displayState) = 0;
        virtual HRESULT STDMETHODCALLTYPE UnadviseCredentialAsync(UINT providerIndex, UINT credentialIndex) = 0;
        virtual HRESULT STDMETHODCALLTYPE UnadviseCredProvsAsync() = 0;
        virtual HRESULT STDMETHODCALLTYPE Shutdown() = 0;
        virtual HRESULT STDMETHODCALLTYPE CheckProviderAvailability(_CREDENTIAL_PROVIDER_USAGE_SCENARIO usageScenario, ULONG flags, const USHORT* providerId, int* available) = 0;
        virtual HRESULT STDMETHODCALLTYPE OnWebDialogVisibilityChangeAsync(UINT providerIndex, UINT credentialIndex, int isVisible) = 0;
        virtual HRESULT STDMETHODCALLTYPE SetUserSuggestionAsync(const USHORT* userSuggestion) = 0;
    };

    // Root interface requested by the old LogonUI/CredUI consumer.
    class IOldCredProvFramework : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE InitializeAsync(CREDENTIAL_SCENARIO scenario, void* autoLogonManager, void* callback, USHORT reserved) = 0;
        virtual HRESULT STDMETHODCALLTYPE StartCredProvsAsync(_CREDENTIAL_PROVIDER_USAGE_SCENARIO usageScenario, ULONG flags, void* serialization, const GUID* providerFilter, const UCHAR* contextBytes, UINT contextByteCount) = 0;
        virtual HRESULT STDMETHODCALLTYPE AdviseCredProvsAsync() = 0;
        virtual HRESULT STDMETHODCALLTYPE EnumerateAllCredentialsAsync() = 0;
        virtual HRESULT STDMETHODCALLTYPE EnumerateTilesForProviderAsync(UINT providerIndex, CREDENTIALSCHANGED_STATE state) = 0;
        virtual HRESULT STDMETHODCALLTYPE AdviseCredentialAsync(UINT providerIndex, UINT credentialIndex, HWND__* hwnd) = 0;
        virtual HRESULT STDMETHODCALLTYPE SelectCredentialAsync(UINT providerIndex, UINT credentialIndex, TILE_SELECTION_FLAGS flags) = 0;
        virtual HRESULT STDMETHODCALLTYPE GetSerializationAsync(UINT providerIndex, UINT credentialIndex, void* status) = 0;
        virtual HRESULT STDMETHODCALLTYPE GetPicturePasswordSerializationAsync(UINT providerIndex, UINT credentialIndex, void* status, void* inspectable) = 0;
        virtual HRESULT STDMETHODCALLTYPE ReportResultAsync(UINT providerIndex, long ntstatus, long substatus, const USHORT* statusText) = 0;
        virtual HRESULT STDMETHODCALLTYPE SetStringDataAsync(UINT providerIndex, UINT credentialIndex, ULONG fieldId, const USHORT* value) = 0;
        virtual HRESULT STDMETHODCALLTYPE OnCommandLinkClickedAsync(UINT providerIndex, UINT credentialIndex, ULONG fieldId) = 0;
        virtual HRESULT STDMETHODCALLTYPE SetCheckboxValueAsync(UINT providerIndex, UINT credentialIndex, ULONG fieldId, int checkedValue) = 0;
        virtual HRESULT STDMETHODCALLTYPE SetComboBoxValueAsync(UINT providerIndex, UINT credentialIndex, ULONG fieldId, ULONG selectedItem) = 0;
        virtual HRESULT STDMETHODCALLTYPE DisconnectCredentialsAsync() = 0;
        virtual HRESULT STDMETHODCALLTYPE BuildUserTileAsync(_CREDENTIAL_PROVIDER_USAGE_SCENARIO usageScenario) = 0;
        virtual HRESULT STDMETHODCALLTYPE SetDisplayStateAsync(_CREDENTIAL_PROVIDER_DISPLAY_STATE_FLAGS displayState) = 0;
        virtual HRESULT STDMETHODCALLTYPE UnadviseCredentialAsync(UINT providerIndex, UINT credentialIndex) = 0;
        virtual HRESULT STDMETHODCALLTYPE UnadviseCredProvsAsync() = 0;
        virtual HRESULT STDMETHODCALLTYPE Shutdown() = 0;
        virtual HRESULT STDMETHODCALLTYPE CheckProviderAvailability(_CREDENTIAL_PROVIDER_USAGE_SCENARIO usageScenario, ULONG flags, const USHORT* providerId, int* available) = 0;
    };

    // Secondary interfaces are queried separately from the current root and
    // re-exposed through one old-framework COM identity.
    class ICredProvThreadInit : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE OnThreadInitComplete() = 0;
        virtual HRESULT STDMETHODCALLTYPE OnThreadInitError(HRESULT result) = 0;
        virtual HRESULT STDMETHODCALLTYPE GetAutoLogonManager(void** autoLogonManager) = 0;
    };

    class ICredentialProviderEventsCompat : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE CredentialsChanged(ULONG_PTR adviseContext) = 0;
    };

    // Bio feedback gained a distinct accessibility string in the current ABI.
    // The old single text value is supplied for both new arguments.
    class IOldCredProvBioEvents : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE BioFeedbackVisualStateChanged(ULONG_PTR adviseContext, CREDENTIAL_PROVIDER_FEEDBACK_VISUAL_STATE state, const USHORT* text) = 0;
        virtual HRESULT STDMETHODCALLTYPE BioFeedbackVisualStateChangedWithPriority(ULONG_PTR adviseContext, CREDENTIAL_PROVIDER_FEEDBACK_VISUAL_STATE state, const USHORT* text, BIO_FEEDBACK_PRIORITY priority) = 0;
        virtual HRESULT STDMETHODCALLTYPE CancelBioFeedbackVisualState(ULONG_PTR adviseContext) = 0;
    };

    class INewCredProvBioEvents : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE BioFeedbackVisualStateChanged(ULONG_PTR adviseContext, CREDENTIAL_PROVIDER_FEEDBACK_VISUAL_STATE state, const USHORT* label, const USHORT* accessibility) = 0;
        virtual HRESULT STDMETHODCALLTYPE BioFeedbackVisualStateChangedWithPriority(ULONG_PTR adviseContext, CREDENTIAL_PROVIDER_FEEDBACK_VISUAL_STATE state, const USHORT* label, const USHORT* accessibility, BIO_FEEDBACK_PRIORITY priority) = 0;
        virtual HRESULT STDMETHODCALLTYPE CancelBioFeedbackVisualState(ULONG_PTR adviseContext) = 0;
    };

    class IGreetingFormatterCompat : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE FormatGreeting(GREETING_TYPE greetingType, void* userSid, USHORT** text) = 0;
        virtual HRESULT STDMETHODCALLTYPE FormatGreetingForCredentialProviderUser(GREETING_TYPE greetingType, void* user, USHORT** text) = 0;
    };


    // Only adapt requests belonging to the recovered old framework identity.
    // Unknown/new interfaces are left to the real class factory unchanged.
    bool IsOldFrameworkRiid(REFIID riid)
    {
        return riid == IID_IUnknown
            || riid == IID_OldCredProvFramework
            || riid == IID_CredProvThreadInit
            || riid == IID_CredentialProviderEvents
            || riid == IID_OldCredProvBioEvents
            || riid == IID_GreetingFormatter
            || riid == IID_IAgileObject
            || riid == IID_IMarshal;
    }

    // Present the complete old COM identity while forwarding work to a current
    // CredProvHost.dll instance and translating only the changed signatures.
    class CCredentialProviderFrameworkWrapper final :
        public IOldCredProvFramework,
        public ICredProvThreadInit,
        public ICredentialProviderEventsCompat,
        public IOldCredProvBioEvents,
        public IGreetingFormatterCompat,
        public IAgileObject,
        public IMarshal
    {
    public:
        explicit CCredentialProviderFrameworkWrapper(INewCredProvFramework* actualRoot)
            : m_actualRoot(actualRoot),
              m_refCount(1)
        {
        }

        // Cache each current secondary interface once. QueryInterface on this
        // wrapper then returns stable wrapper subobjects with one COM lifetime.
        HRESULT Initialize() noexcept
        {
            HRESULT result = m_actualRoot->QueryInterface(IID_CredProvThreadInit, reinterpret_cast<void**>(&m_actualThreadInit));
            if (FAILED(result))
            {
                return result;
            }

            result = m_actualRoot->QueryInterface(IID_CredentialProviderEvents, reinterpret_cast<void**>(&m_actualEvents));
            if (FAILED(result))
            {
                return result;
            }

            result = m_actualRoot->QueryInterface(IID_NewCredProvBioEvents, reinterpret_cast<void**>(&m_actualBioEvents));
            if (FAILED(result))
            {
                return result;
            }

            result = m_actualRoot->QueryInterface(IID_GreetingFormatter, reinterpret_cast<void**>(&m_actualGreetingFormatter));
            if (FAILED(result))
            {
                return result;
            }

            result = m_actualRoot->QueryInterface(IID_IAgileObject, reinterpret_cast<void**>(&m_actualAgileObject));
            if (FAILED(result))
            {
                return result;
            }

            result = m_actualRoot->QueryInterface(IID_IMarshal, reinterpret_cast<void**>(&m_actualMarshal));
            return result;
        }

        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** object) override
        {
            if (!object)
            {
                return E_POINTER;
            }

            *object = nullptr;
            if (riid == IID_IUnknown || riid == IID_OldCredProvFramework)
            {
                *object = static_cast<IOldCredProvFramework*>(this);
            }
            else if (riid == IID_CredProvThreadInit)
            {
                *object = static_cast<ICredProvThreadInit*>(this);
            }
            else if (riid == IID_CredentialProviderEvents)
            {
                *object = static_cast<ICredentialProviderEventsCompat*>(this);
            }
            else if (riid == IID_OldCredProvBioEvents)
            {
                *object = static_cast<IOldCredProvBioEvents*>(this);
            }
            else if (riid == IID_GreetingFormatter)
            {
                *object = static_cast<IGreetingFormatterCompat*>(this);
            }
            else if (riid == IID_IAgileObject)
            {
                *object = static_cast<IAgileObject*>(this);
            }
            else if (riid == IID_IMarshal)
            {
                *object = static_cast<IMarshal*>(this);
            }
            else
            {
                return E_NOINTERFACE;
            }

            AddRef();
            return S_OK;
        }

        ULONG STDMETHODCALLTYPE AddRef() override
        {
            return static_cast<ULONG>(InterlockedIncrement(&m_refCount));
        }

        ULONG STDMETHODCALLTYPE Release() override
        {
            const ULONG newRefCount = static_cast<ULONG>(InterlockedDecrement(&m_refCount));
            if (newRefCount == 0)
            {
                delete this;
            }
            return newRefCount;
        }

        // Old InitializeAsync has no feature mask. Feature bit 0 tells the
        // current framework that the consumer supports credential-method
        // filtering used by the recovered tile contract.
        HRESULT STDMETHODCALLTYPE InitializeAsync(CREDENTIAL_SCENARIO scenario, void* autoLogonManager, void* callback, USHORT reserved) override
        {
            InterlockedOr(&g_frameworkCalls, 1);
            CCredProvFrameworkCallbackValidator* validator = nullptr;
            if (callback)
            {
                validator = new (std::nothrow) CCredProvFrameworkCallbackValidator(
                    reinterpret_cast<IUnknown*>(callback));
                if (!validator)
                {
                    return ReportFailure(L"Allocate tile callback validator", E_OUTOFMEMORY);
                }
            }

            const HRESULT result = m_actualRoot->InitializeAsync(
                scenario,
                1,
                autoLogonManager,
                validator
                    ? static_cast<ICredProvFrameworkCallbackCompat*>(validator)
                    : callback,
                reserved);
            if (validator)
            {
                validator->Release();
            }
            return ReportFailure(L"InitializeAsync", result);
        }

        // Old StartCredProvsAsync has no user-suggestion argument. Supply the
        // required LSA package context when the caller omitted it, and pass a
        // null suggestion in the new trailing slot.
        HRESULT STDMETHODCALLTYPE StartCredProvsAsync(_CREDENTIAL_PROVIDER_USAGE_SCENARIO usageScenario, ULONG flags, void* serialization, const GUID* providerFilter, const UCHAR* contextBytes, UINT contextByteCount) override
        {
            InterlockedOr(&g_frameworkCalls, 2);
            if (contextByteCount == 0
                && !GetLegacyAuthPackageContext(&contextBytes, &contextByteCount))
            {
                return ReportFailure(
                    L"Resolve legacy authentication packages",
                    HRESULT_FROM_WIN32(ERROR_NOT_FOUND));
            }

            const HRESULT result = ReportFailure(
                L"StartCredProvsAsync",
                m_actualRoot->StartCredProvsAsync(
                    usageScenario,
                    flags,
                    serialization,
                    providerFilter,
                    contextBytes,
                    contextByteCount,
                    nullptr));
            if (SUCCEEDED(result))
            {
                ArmPromptWatchdog();
            }
            return result;
        }

        // These calls are tracked because successful asynchronous submission
        // does not prove that the corresponding callback payload was consumed.
        HRESULT STDMETHODCALLTYPE AdviseCredProvsAsync() override { InterlockedOr(&g_frameworkCalls, 4); return ReportFailure(L"AdviseCredProvsAsync", m_actualRoot->AdviseCredProvsAsync()); }
        HRESULT STDMETHODCALLTYPE EnumerateAllCredentialsAsync() override { InterlockedOr(&g_frameworkCalls, 8); return ReportFailure(L"EnumerateAllCredentialsAsync", m_actualRoot->EnumerateAllCredentialsAsync()); }
        HRESULT STDMETHODCALLTYPE EnumerateTilesForProviderAsync(UINT providerIndex, CREDENTIALSCHANGED_STATE state) override { InterlockedOr(&g_frameworkCalls, 16); return ReportFailure(L"EnumerateTilesForProviderAsync", m_actualRoot->EnumerateTilesForProviderAsync(providerIndex, state)); }
        HRESULT STDMETHODCALLTYPE AdviseCredentialAsync(UINT providerIndex, UINT credentialIndex, HWND__* hwnd) override
        {
            if (hwnd)
            {
                MarkPromptUiActive();
            }
            return m_actualRoot->AdviseCredentialAsync(providerIndex, credentialIndex, hwnd);
        }
        HRESULT STDMETHODCALLTYPE SelectCredentialAsync(UINT providerIndex, UINT credentialIndex, TILE_SELECTION_FLAGS flags) override
        {
            MarkPromptUiActive();
            return m_actualRoot->SelectCredentialAsync(providerIndex, credentialIndex, flags);
        }
        HRESULT STDMETHODCALLTYPE GetSerializationAsync(UINT providerIndex, UINT credentialIndex, void* status) override
        {
            return ReportFailure(
                L"GetSerializationAsync",
                m_actualRoot->GetSerializationAsync(providerIndex, credentialIndex, status));
        }
        HRESULT STDMETHODCALLTYPE GetPicturePasswordSerializationAsync(UINT providerIndex, UINT credentialIndex, void* status, void* inspectable) override { return m_actualRoot->GetPicturePasswordSerializationAsync(providerIndex, credentialIndex, status, inspectable); }
        // Old ReportResultAsync supplies one status string; the two status-text
        // fields added by the current interface have no old-side equivalent.
        HRESULT STDMETHODCALLTYPE ReportResultAsync(UINT providerIndex, long ntstatus, long substatus, const USHORT* statusText) override { return m_actualRoot->ReportResultAsync(providerIndex, ntstatus, substatus, statusText, nullptr, nullptr); }
        HRESULT STDMETHODCALLTYPE SetStringDataAsync(UINT providerIndex, UINT credentialIndex, ULONG fieldId, const USHORT* value) override { return m_actualRoot->SetStringDataAsync(providerIndex, credentialIndex, fieldId, value); }
        HRESULT STDMETHODCALLTYPE OnCommandLinkClickedAsync(UINT providerIndex, UINT credentialIndex, ULONG fieldId) override { return m_actualRoot->OnCommandLinkClickedAsync(providerIndex, credentialIndex, fieldId); }
        HRESULT STDMETHODCALLTYPE SetCheckboxValueAsync(UINT providerIndex, UINT credentialIndex, ULONG fieldId, int checkedValue) override { return m_actualRoot->SetCheckboxValueAsync(providerIndex, credentialIndex, fieldId, checkedValue); }
        HRESULT STDMETHODCALLTYPE SetComboBoxValueAsync(UINT providerIndex, UINT credentialIndex, ULONG fieldId, ULONG selectedItem) override { return m_actualRoot->SetComboBoxValueAsync(providerIndex, credentialIndex, fieldId, selectedItem); }
        HRESULT STDMETHODCALLTYPE DisconnectCredentialsAsync() override { return m_actualRoot->DisconnectCredentialsAsync(); }
        HRESULT STDMETHODCALLTYPE BuildUserTileAsync(_CREDENTIAL_PROVIDER_USAGE_SCENARIO usageScenario) override { return m_actualRoot->BuildUserTileAsync(usageScenario); }
        HRESULT STDMETHODCALLTYPE SetDisplayStateAsync(_CREDENTIAL_PROVIDER_DISPLAY_STATE_FLAGS displayState) override
        {
            return m_actualRoot->SetDisplayStateAsync(displayState);
        }
        HRESULT STDMETHODCALLTYPE UnadviseCredentialAsync(UINT providerIndex, UINT credentialIndex) override { return m_actualRoot->UnadviseCredentialAsync(providerIndex, credentialIndex); }
        HRESULT STDMETHODCALLTYPE UnadviseCredProvsAsync() override { return m_actualRoot->UnadviseCredProvsAsync(); }
        HRESULT STDMETHODCALLTYPE Shutdown() override { return m_actualRoot->Shutdown(); }
        HRESULT STDMETHODCALLTYPE CheckProviderAvailability(_CREDENTIAL_PROVIDER_USAGE_SCENARIO usageScenario, ULONG flags, const USHORT* providerId, int* available) override { return m_actualRoot->CheckProviderAvailability(usageScenario, flags, providerId, available); }

        HRESULT STDMETHODCALLTYPE OnThreadInitComplete() override { return m_actualThreadInit->OnThreadInitComplete(); }
        HRESULT STDMETHODCALLTYPE OnThreadInitError(HRESULT result) override { return m_actualThreadInit->OnThreadInitError(result); }
        HRESULT STDMETHODCALLTYPE GetAutoLogonManager(void** autoLogonManager) override { return m_actualThreadInit->GetAutoLogonManager(autoLogonManager); }

        HRESULT STDMETHODCALLTYPE CredentialsChanged(ULONG_PTR adviseContext) override { return m_actualEvents->CredentialsChanged(adviseContext); }

        // Duplicate the old bio-feedback text as both visible and accessibility
        // text required by the current interface.
        HRESULT STDMETHODCALLTYPE BioFeedbackVisualStateChanged(ULONG_PTR adviseContext, CREDENTIAL_PROVIDER_FEEDBACK_VISUAL_STATE state, const USHORT* text) override
        {
            return m_actualBioEvents->BioFeedbackVisualStateChanged(adviseContext, state, text, text);
        }

        HRESULT STDMETHODCALLTYPE BioFeedbackVisualStateChangedWithPriority(ULONG_PTR adviseContext, CREDENTIAL_PROVIDER_FEEDBACK_VISUAL_STATE state, const USHORT* text, BIO_FEEDBACK_PRIORITY priority) override
        {
            return m_actualBioEvents->BioFeedbackVisualStateChangedWithPriority(adviseContext, state, text, text, priority);
        }

        HRESULT STDMETHODCALLTYPE CancelBioFeedbackVisualState(ULONG_PTR adviseContext) override
        {
            return m_actualBioEvents->CancelBioFeedbackVisualState(adviseContext);
        }

        HRESULT STDMETHODCALLTYPE FormatGreeting(GREETING_TYPE greetingType, void* userSid, USHORT** text) override
        {
            return m_actualGreetingFormatter->FormatGreeting(greetingType, userSid, text);
        }

        HRESULT STDMETHODCALLTYPE FormatGreetingForCredentialProviderUser(GREETING_TYPE greetingType, void* user, USHORT** text) override
        {
            return m_actualGreetingFormatter->FormatGreetingForCredentialProviderUser(greetingType, user, text);
        }

        // Forward the real free-threaded marshaler so cross-apartment consumers
        // retain the agility semantics of the underlying framework object.
        HRESULT STDMETHODCALLTYPE GetUnmarshalClass(REFIID riid, void* object, DWORD destinationContext, void* destinationContextPtr, DWORD marshalFlags, CLSID* classId) override
        {
            return m_actualMarshal->GetUnmarshalClass(riid, object, destinationContext, destinationContextPtr, marshalFlags, classId);
        }

        HRESULT STDMETHODCALLTYPE GetMarshalSizeMax(REFIID riid, void* object, DWORD destinationContext, void* destinationContextPtr, DWORD marshalFlags, DWORD* size) override
        {
            return m_actualMarshal->GetMarshalSizeMax(riid, object, destinationContext, destinationContextPtr, marshalFlags, size);
        }

        HRESULT STDMETHODCALLTYPE MarshalInterface(IStream* stream, REFIID riid, void* object, DWORD destinationContext, void* destinationContextPtr, DWORD marshalFlags) override
        {
            return m_actualMarshal->MarshalInterface(stream, riid, object, destinationContext, destinationContextPtr, marshalFlags);
        }

        HRESULT STDMETHODCALLTYPE UnmarshalInterface(IStream* stream, REFIID riid, void** object) override
        {
            return m_actualMarshal->UnmarshalInterface(stream, riid, object);
        }

        HRESULT STDMETHODCALLTYPE ReleaseMarshalData(IStream* stream) override
        {
            return m_actualMarshal->ReleaseMarshalData(stream);
        }

        HRESULT STDMETHODCALLTYPE DisconnectObject(DWORD reserved) override
        {
            return m_actualMarshal->DisconnectObject(reserved);
        }

    private:
        ~CCredentialProviderFrameworkWrapper()
        {
            if (m_actualMarshal)
            {
                m_actualMarshal->Release();
            }
            if (m_actualAgileObject)
            {
                m_actualAgileObject->Release();
            }
            if (m_actualGreetingFormatter)
            {
                m_actualGreetingFormatter->Release();
            }
            if (m_actualBioEvents)
            {
                m_actualBioEvents->Release();
            }
            if (m_actualEvents)
            {
                m_actualEvents->Release();
            }
            if (m_actualThreadInit)
            {
                m_actualThreadInit->Release();
            }
            if (m_actualRoot)
            {
                m_actualRoot->Release();
            }
        }

        INewCredProvFramework* m_actualRoot;
        ICredProvThreadInit* m_actualThreadInit = nullptr;
        ICredentialProviderEventsCompat* m_actualEvents = nullptr;
        INewCredProvBioEvents* m_actualBioEvents = nullptr;
        IGreetingFormatterCompat* m_actualGreetingFormatter = nullptr;
        IAgileObject* m_actualAgileObject = nullptr;
        IMarshal* m_actualMarshal = nullptr;
        LONG m_refCount;
    };

    // Intercept creation only when an old framework IID is requested. The real
    // factory still services unrelated classes and current interface requests.
    class CCredentialProviderClassFactory final : public IClassFactory
    {
    public:
        explicit CCredentialProviderClassFactory(IClassFactory* actualFactory)
            : m_actualFactory(actualFactory),
              m_refCount(1)
        {
        }

        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** object) override
        {
            if (!object)
            {
                return E_POINTER;
            }

            *object = nullptr;
            if (riid == IID_IUnknown || riid == IID_IClassFactory)
            {
                *object = static_cast<IClassFactory*>(this);
                AddRef();
                return S_OK;
            }

            return E_NOINTERFACE;
        }

        ULONG STDMETHODCALLTYPE AddRef() override
        {
            return static_cast<ULONG>(InterlockedIncrement(&m_refCount));
        }

        ULONG STDMETHODCALLTYPE Release() override
        {
            const ULONG newRefCount = static_cast<ULONG>(InterlockedDecrement(&m_refCount));
            if (newRefCount == 0)
            {
                m_actualFactory->Release();
                delete this;
            }
            return newRefCount;
        }

        HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID riid, void** object) override
        {
            if (!object)
            {
                return E_POINTER;
            }

            *object = nullptr;
            // A current caller must receive the native object, not an old-layout
            // wrapper that would hide methods added at the vtable tail.
            if (!IsOldFrameworkRiid(riid))
            {
                return m_actualFactory->CreateInstance(outer, riid, object);
            }

            INewCredProvFramework* actualRoot = nullptr;
            const HRESULT result = m_actualFactory->CreateInstance(
                outer,
                IID_NewCredProvFramework,
                reinterpret_cast<void**>(&actualRoot));
            if (FAILED(result))
            {
                return ReportFailure(L"Create newest framework instance", result);
            }

            auto* wrapper = new (std::nothrow) CCredentialProviderFrameworkWrapper(actualRoot);
            if (!wrapper)
            {
                actualRoot->Release();
                return ReportFailure(L"Allocate framework adapter", E_OUTOFMEMORY);
            }

            const HRESULT initResult = wrapper->Initialize();
            if (FAILED(initResult))
            {
                wrapper->Release();
                return ReportFailure(L"Query newest framework interfaces", initResult);
            }

            const HRESULT queryResult = wrapper->QueryInterface(riid, object);
            wrapper->Release();
            return ReportFailure(L"Expose legacy framework interface", queryResult);
        }

        HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override
        {
            return m_actualFactory->LockServer(lock);
        }

    private:
        IClassFactory* m_actualFactory;
        LONG m_refCount;
    };

    // Load the installed System32 implementation explicitly. Loading by bare
    // name from this proxy could resolve the proxy again and recurse.
    HMODULE GetCredProvHostDll()
    {
        if (g_credProvHost)
        {
            return g_credProvHost;
        }

        wchar_t systemDir[MAX_PATH] = {};
        if (!GetSystemDirectoryW(systemDir, MAX_PATH))
        {
            ReportFailure(L"Locate Windows system directory", HRESULT_FROM_WIN32(GetLastError()));
            return nullptr;
        }

        if (wcscat_s(systemDir, MAX_PATH, L"\\CredProvHost.dll") != 0)
        {
            ReportFailure(L"Build CredProvHost.dll path", HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER));
            return nullptr;
        }

        g_credProvHost = LoadLibraryW(systemDir);
        if (!g_credProvHost)
        {
            ReportFailure(L"Load CredProvHost.dll", HRESULT_FROM_WIN32(GetLastError()));
        }
        return g_credProvHost;
    }

}

// Preserve the original DLL exports so the proxy remains usable by COM and
// WinRT callers. Only COM class factories are wrapped; other exports forward.
extern "C" __declspec(dllexport) HRESULT __stdcall DllCanUnloadNow()
{
    if (!g_credProvHost)
    {
        return S_OK;
    }

    const auto canUnloadNow = reinterpret_cast<HRESULT (STDAPICALLTYPE*)()>(GetProcAddress(g_credProvHost, "DllCanUnloadNow"));
    if (!canUnloadNow)
    {
        return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
    }

    return canUnloadNow();
}

extern "C" __declspec(dllexport) HRESULT WINAPI DllGetActivationFactory(HSTRING classId, void* factory)
{
    HMODULE module = GetCredProvHostDll();
    if (!module)
    {
        return HRESULT_FROM_WIN32(ERROR_DLL_NOT_FOUND);
    }

    const auto getActivationFactory = reinterpret_cast<HRESULT (WINAPI*)(HSTRING, void*)>(GetProcAddress(module, "DllGetActivationFactory"));
    if (!getActivationFactory)
    {
        return ReportFailure(L"Find DllGetActivationFactory export", HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND));
    }

    if (IsBypassModeEnabled())
    {
        return getActivationFactory(classId, factory);
    }

    return ReportFailure(L"Get WinRT activation factory", getActivationFactory(classId, factory));
}

extern "C" __declspec(dllexport) HRESULT __stdcall DllGetClassObject(REFCLSID rclsid, REFIID riid, void** object)
{
    if (!object)
    {
        return E_POINTER;
    }

    *object = nullptr;
    HMODULE module = GetCredProvHostDll();
    if (!module)
    {
        return HRESULT_FROM_WIN32(ERROR_DLL_NOT_FOUND);
    }

    const auto getClassObject = reinterpret_cast<HRESULT (STDAPICALLTYPE*)(REFCLSID, REFIID, void**)>(GetProcAddress(module, "DllGetClassObject"));
    if (!getClassObject)
    {
        return ReportFailure(L"Find DllGetClassObject export", HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND));
    }

    // Once a failure has persisted pass-through mode, return the installed
    // class object unchanged. Existing wrapper instances keep their original
    // ABI until their process exits; changing one in place would be unsafe.
    if (IsBypassModeEnabled())
    {
        return getClassObject(rclsid, riid, object);
    }

    // Non-factory class-object requests do not expose CreateInstance and can be
    // returned directly. Wrapping the factory is what permits IID translation.
    if (riid != IID_IClassFactory && riid != IID_IUnknown)
    {
        return ReportFailure(L"Get requested class object", getClassObject(rclsid, riid, object));
    }

    IClassFactory* actualFactory = nullptr;
    const HRESULT result = getClassObject(rclsid, IID_IClassFactory, reinterpret_cast<void**>(&actualFactory));
    if (FAILED(result))
    {
        return ReportFailure(L"Get newest framework class factory", result);
    }

    auto* wrapper = new (std::nothrow) CCredentialProviderClassFactory(actualFactory);
    if (!wrapper)
    {
        actualFactory->Release();
        return ReportFailure(L"Allocate class factory adapter", E_OUTOFMEMORY);
    }

    *object = static_cast<IClassFactory*>(wrapper);
    return S_OK;
}

// No loader-lock hooks or MinHook detours: initialization is deferred until an
// exported factory is requested. This avoids install-dependent loader failures.
BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(module);
    }
    return TRUE;
}
