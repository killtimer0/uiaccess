#include <windows.h>
#include <tchar.h>
#include "uiaccess.h"
#include "resource.h"

static HINSTANCE g_hInstance;
static HWND g_hdlg = NULL;
static BOOL g_fHasUIAccess;
static BOOL g_fAlwaysTop = TRUE;

static void SetTopmostStatus(BOOL fAlwaysTop)
{
	DWORD dwFlags, dwExStyle;
	HWND hwndIns;

	dwFlags = SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE;
	hwndIns = fAlwaysTop ? HWND_TOPMOST : HWND_NOTOPMOST;
	SetWindowPos(g_hdlg, hwndIns, 0, 0, 0, 0, dwFlags);

	dwExStyle = (DWORD)GetWindowLongPtr(g_hdlg, GWL_EXSTYLE);
	g_fAlwaysTop = dwExStyle & WS_EX_TOPMOST;
	CheckDlgButton(g_hdlg, IDC_MAIN_TOP, g_fAlwaysTop);
}

static INT_PTR CALLBACK DialogProc(HWND hdlg, UINT uMsg, WPARAM wParam, LPARAM lParam){
    switch (uMsg){
    case WM_COMMAND:
		{
			UINT id = LOWORD(wParam), code = HIWORD(wParam);
			switch (id){
			case IDOK:
			case IDCANCEL:
				EndDialog(hdlg, id);
                break;

			case IDC_MAIN_TOP:
				SetTopmostStatus(!g_fAlwaysTop);
				break;

            case IDC_MAIN_OPEN_TASKMGR:
                ShellExecute(NULL, NULL, TEXT("taskmgr"), NULL, NULL, SW_SHOWDEFAULT);
                break;

            }
        }
		return 0;

    case WM_INITDIALOG:
		g_hdlg = hdlg;
		CheckDlgButton(hdlg, IDC_MAIN_UIACCESS, g_fHasUIAccess);
		SetTopmostStatus(g_fAlwaysTop);
		SetDlgItemText(hdlg, IDC_MAIN_CMD, GetCommandLine());
        return TRUE;

    }
    return FALSE;
}

static int InitInstance(HINSTANCE hInstance)
{
	DWORD dwErr;
	INT_PTR iResult;

	dbgstart();

	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

	dwErr = PrepareForUIAccess();
	if (ERROR_SUCCESS != dwErr)
		dbg("UIAccess error: 0x%08X\n", dwErr);
	g_fHasUIAccess = ERROR_SUCCESS == dwErr;

	g_hInstance = hInstance;

	iResult = DialogBox(g_hInstance, MAKEINTRESOURCE(IDD_MAIN), NULL, DialogProc);
	g_hdlg = NULL;

	CoUninitialize();

	dbgend();

	return (int)iResult;
}

#ifdef MYTOOLCHAIN
void main(){
	ExitProcess(InitInstance(GetModuleHandle(NULL)));
}

#else
int APIENTRY _tWinMain(
	_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPTSTR lpCmdLine,
	_In_ int nCmdShow
)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	UNREFERENCED_PARAMETER(nCmdShow);
	return InitInstance(hInstance);
}
#endif

