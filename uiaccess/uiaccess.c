#include "uiaccess.h"

#ifdef MYTOOLCHAIN
EXTERN_C BOOL WINBASEAPI WINAPI K32EnumProcesses(DWORD *lpidProcess, DWORD cb, DWORD *cbNeeded);
#define EnumProcesses	K32EnumProcesses
#else
#include <Psapi.h>
#endif

static DWORD tcshash(LPCTSTR lpszText, LPTSTR lpHex)
{
	DWORD result = 0;
	LPCTSTR p = lpszText;
	int c, i;

	while (c = *p++)
	{
		result = result * 131 + c;
	}

	if (lpHex)
	{
		for (i = 7; ~i; --i)
		{
			c = (result >> (i << 2)) & 15;
			if (c < 10)
				c += '0';
			else
				c += 'A' - 10;
			lpHex[i] = c;
		}
		lpHex[8] = TEXT('\0');
	}

	return result;
}

static HANDLE LookupForFirstSystemToken()
{
	HANDLE hFinalToken = NULL;
	PRIVILEGE_SET ps;
	DWORD cbSize, dwSize, i;
	DWORD *pids;
	const DWORD dwMaxPids = 16384;

	ps.PrivilegeCount = 1;
	ps.Control = PRIVILEGE_SET_ALL_NECESSARY;

	if (LookupPrivilegeValue(NULL, SE_TCB_NAME, &ps.Privilege[0].Luid))
	{
		pids = (DWORD*)LocalAlloc(LPTR, dwMaxPids * sizeof(*pids));
		if (pids)
		{
			if (EnumProcesses(pids, dwMaxPids * sizeof (*pids), &cbSize))
			{
				dwSize = cbSize >> 2;

				for (i = 0; i < dwSize; ++i)
				{
					HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pids[i]);
					if (hProcess)
					{
						HANDLE hToken;
						if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken))
						{
							BOOL fTcbPrivileges;

							if (PrivilegeCheck(hToken, &ps, &fTcbPrivileges) && fTcbPrivileges)
							{
								if (!DuplicateTokenEx(
									hToken,
									TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
									NULL,
									SecurityAnonymous,
									TokenPrimary,
									&hFinalToken
								))
								{
									hFinalToken = NULL;
								}
							}
							CloseHandle(hToken);
						}
						CloseHandle(hProcess);
					}

					if (hFinalToken)
						break;

				}
			}
			LocalFree(pids);
		}
	}

	return hFinalToken;
}

#define PIPE_UIACCESS_PREFIX TEXT("\\\\.\\pipe\\KtUIAccess_0x")

// Step1
static DWORD CreateUIAccessToken(HANDLE hPipe, LPCTSTR lpName, HANDLE *phToken)
{
	HANDLE hToken;
	DWORD dwErr;

	// Prepare token for Step3
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &hToken))
	{
		SECURITY_ATTRIBUTES sa;
		DWORD dwRetLen, fUIAccess;
		HANDLE hTokenSelf;

		sa.nLength = sizeof (sa);
		sa.lpSecurityDescriptor = NULL;
		sa.bInheritHandle = TRUE;
		if (DuplicateTokenEx(
			hToken,
			TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
			&sa,
			SecurityAnonymous,
			TokenPrimary,
			&hTokenSelf
			))
		{
			HANDLE hTokenSystem;
			// Prepare token for Step2
			hTokenSystem = LookupForFirstSystemToken();
			if (hTokenSystem)
			{
				STARTUPINFO si = {sizeof (si)};
				PROCESS_INFORMATION pi;

				if (CreateProcessAsUser(hTokenSystem, lpName, NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
				{
					ConnectNamedPipe(hPipe, NULL);
					WriteFile(hPipe, &hTokenSelf, sizeof (hTokenSelf), NULL, NULL);

					// Wait for step2
					WaitForSingleObject(pi.hProcess, INFINITE);
					CloseHandle(pi.hProcess), CloseHandle(pi.hThread);

					dwErr = ERROR_SUCCESS;
				}
				else
				{
					dwErr = GetLastError();
				}
				CloseHandle(hTokenSystem);
			}
			else
			{
				dwErr = ERROR_NOT_FOUND;
			}

			if (ERROR_SUCCESS == dwErr)
			{
				if (GetTokenInformation(hTokenSelf, TokenUIAccess, &fUIAccess, sizeof (fUIAccess), &dwRetLen) && fUIAccess)
				{
					// Done.
					*phToken = hTokenSelf;
				}
				else
				{
					CloseHandle(hTokenSelf);
					hTokenSelf = NULL;
					dwErr = ERROR_ACCESS_DENIED;
				}
			}
		}
		else
		{
			dwErr = GetLastError();
		}
		CloseHandle(hToken);
	}
	else
	{
		dwErr = GetLastError();
	}

	return dwErr;
}

static BOOL CheckForUIAccess(DWORD *pdwErr, DWORD *pfUIAccess)
{
	BOOL result = FALSE;
	HANDLE hToken;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		DWORD dwRetLen;

		if (GetTokenInformation(hToken, TokenUIAccess, pfUIAccess, sizeof (*pfUIAccess), &dwRetLen))
		{
			result = TRUE;
		}
		else
		{
			*pdwErr = GetLastError();
		}
		CloseHandle(hToken);
	}
	else
	{
		*pdwErr = GetLastError();
	}

	return result;
}

DWORD PrepareForUIAccess()
{
	TCHAR buf[MAX_PATH];
	TCHAR szName[8 + ARRAYSIZE(PIPE_UIACCESS_PREFIX)];
	HANDLE hPipe;
	DWORD dwErr;
	DWORD fUIAccess;

	if (CheckForUIAccess(&dwErr, &fUIAccess))
	{
		// Step3
		if (fUIAccess)
			return ERROR_SUCCESS;
	}
	else
		return dwErr;

	memcpy(szName, PIPE_UIACCESS_PREFIX, sizeof (PIPE_UIACCESS_PREFIX));
	GetModuleFileName(NULL, buf, MAX_PATH);
	tcshash(buf, szName + ARRAYSIZE(PIPE_UIACCESS_PREFIX) - 1);

	hPipe = CreateFile(szName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (INVALID_HANDLE_VALUE != hPipe)
	{
		// Step2
		HANDLE hTokenSelf;

		if (ReadFile(hPipe, &hTokenSelf, sizeof (hTokenSelf), NULL, NULL))
		{
			BOOL fUIAccess = TRUE;
			SetTokenInformation(hTokenSelf, TokenUIAccess, &fUIAccess, sizeof (fUIAccess));
		}

		CloseHandle(hPipe);
		ExitProcess(0);
	}
	else
	{
		dwErr = GetLastError();
		if (ERROR_FILE_NOT_FOUND == dwErr)
		{
			BOOL fDone = FALSE;

			hPipe = CreateNamedPipe(
				szName,
				PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
				PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
				1,
				0,
				0,
				0,
				NULL
				);

			if (INVALID_HANDLE_VALUE != hPipe)
			{
				HANDLE hTokenUIAccess;

				dwErr = CreateUIAccessToken(hPipe, buf, &hTokenUIAccess);
				CloseHandle(hPipe);

				if (ERROR_SUCCESS == dwErr)
				{
					STARTUPINFO si;
					PROCESS_INFORMATION pi;

					GetStartupInfo(&si);
					if (CreateProcessAsUser(
						hTokenUIAccess,
						NULL,
						GetCommandLine(),
						NULL,
						NULL,
						FALSE,
						0,
						NULL,
						NULL,
						&si,
						&pi
						))
					{
						fDone = TRUE;
						CloseHandle(pi.hProcess), CloseHandle(pi.hThread);
					}
					else
					{
						dwErr = GetLastError();
					}
					CloseHandle(hTokenUIAccess);
				}

				if (fDone)
					ExitProcess(0);
			}
			else
			{
				dwErr = GetLastError();
			}
		}
	}

	return dwErr;
}

