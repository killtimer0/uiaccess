#include "uiaccess.h"
#include <tlhelp32.h>
#include <tchar.h>

static DWORD DuplicateWinloginToken(DWORD dwSessionId, DWORD dwDesiredAccess, PHANDLE phToken) {
	HANDLE hSnapshot;
	DWORD dwErr;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE != hSnapshot) {
		BOOL bCont, bFound = FALSE;
		PROCESSENTRY32 pe;

		pe.dwSize = sizeof (pe);
		dwErr = ERROR_NOT_FOUND;

		for (bCont = Process32First(hSnapshot, &pe); bCont; bCont = Process32Next(hSnapshot, &pe)) {
			if (0 == _tcsicmp(pe.szExeFile, TEXT("winlogon.exe"))) {
				HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);

				if (hProcess) {
					HANDLE hToken;
					DWORD dwRetLen, sid;

					if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)) {
						if (GetTokenInformation(hToken, TokenSessionId, &sid, sizeof (sid), &dwRetLen) && sid == dwSessionId) {
							bFound = TRUE;
							if (DuplicateTokenEx(hToken, dwDesiredAccess, NULL, SecurityImpersonation, TokenImpersonation, phToken)) {
								dwErr = ERROR_SUCCESS;
							} else {
								dwErr = GetLastError();
							}
						}
						CloseHandle(hToken);
					}
					CloseHandle(hProcess);
				}
			}

			if (bFound) break;
		}

		CloseHandle(hSnapshot);
	} else {
		dwErr = GetLastError();
	}

	return dwErr;
}

static DWORD CreateUIAccessToken(PHANDLE phToken) {
	DWORD dwErr;
	HANDLE hTokenSelf;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &hTokenSelf)) {
		DWORD dwSessionId, dwRetLen;

		if (GetTokenInformation(hTokenSelf, TokenSessionId, &dwSessionId, sizeof (dwSessionId), &dwRetLen)) {
			HANDLE hTokenSystem;

			dwErr = DuplicateWinloginToken(dwSessionId, TOKEN_IMPERSONATE, &hTokenSystem);
			if (ERROR_SUCCESS == dwErr) {
				if (SetThreadToken(NULL, hTokenSystem)) {
					if (DuplicateTokenEx(hTokenSelf, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, NULL, SecurityAnonymous, TokenPrimary, phToken)) {
						BOOL bUIAccess = TRUE;

						if (!SetTokenInformation(*phToken, TokenUIAccess, &bUIAccess, sizeof (bUIAccess))) {
							dwErr = GetLastError();
							CloseHandle(*phToken);
						}
					} else {
						dwErr = GetLastError();
					}
					RevertToSelf();
				} else {
					dwErr = GetLastError();
				}
				CloseHandle(hTokenSystem);
			}
		} else {
			dwErr = GetLastError();
		}

		CloseHandle(hTokenSelf);
	} else {
		dwErr = GetLastError();
	}

	return dwErr;
}

static BOOL CheckForUIAccess(DWORD *pdwErr, DWORD *pfUIAccess) {
	BOOL result = FALSE;
	HANDLE hToken;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		DWORD dwRetLen;

		if (GetTokenInformation(hToken, TokenUIAccess, pfUIAccess, sizeof (*pfUIAccess), &dwRetLen)) {
			result = TRUE;
		} else {
			*pdwErr = GetLastError();
		}
		CloseHandle(hToken);
	} else {
		*pdwErr = GetLastError();
	}

	return result;
}

DWORD PrepareForUIAccess() {
	DWORD dwErr;
	HANDLE hTokenUIAccess;
	BOOL fUIAccess;

	if (CheckForUIAccess(&dwErr, &fUIAccess)) {
		if (fUIAccess) {
			dwErr = ERROR_SUCCESS;
		} else {
			dwErr = CreateUIAccessToken(&hTokenUIAccess);
			if (ERROR_SUCCESS == dwErr) {
				STARTUPINFO si;
				PROCESS_INFORMATION pi;

				GetStartupInfo(&si);
				if (CreateProcessAsUser(hTokenUIAccess, NULL, GetCommandLine(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
					CloseHandle(pi.hProcess), CloseHandle(pi.hThread);
					ExitProcess(0);
				} else {
					dwErr = GetLastError();
				}
			}
		}
	}

	return dwErr;
}