/*
 * Copyright (c) 2026 JackTheRibber0 - https://github.com/JackTheRibber0
 * Licensed under the Apache License, Version 2.0
 *
 * LEGAL DISCLAIMER:
 * This C++ source code and the resulting binary are intended strictly for
 * educational purposes, academic research, and authorized Red Team operations.
 * The author assumes no liability for unauthorized or malicious use.
 */

#include "Miscellaneous.h"

extern "C"
{
	DWORD NtOpenProcSSN = NULL;
	DWORD NtOpenThreadSSN = NULL;
	DWORD NtWaitForSingleObjSSN = NULL;

	DWORD NtAllocVirtualMemSSN = NULL;
	DWORD NtProtectVirtualMemSSN = NULL;
	DWORD NtWriteVirtualMemSSN = NULL;

	DWORD NtCreateThreadExSSN = NULL;
	DWORD NtCloseSSN = NULL;
	DWORD NtQueueSSN = NULL;
	DWORD NtQuerrySystemInfoSSN = NULL;

	UINT_PTR NtOpenProcSyscall = NULL;
	UINT_PTR NtOpenThreadSyscall = NULL;
	UINT_PTR NtWaitForSingleObjSyscall = NULL;

	UINT_PTR NtWriteVirtualMemSyscall = NULL;
	UINT_PTR NtProtectVirtualMemSyscall = NULL;
	UINT_PTR NtAllocVirtualMemSysscall = NULL;

	UINT_PTR NtCreateThreadExSyscall = NULL;
	UINT_PTR NtCloseSyscall = NULL;
	UINT_PTR NtQueueSyscall = NULL;
	UINT_PTR NtQuerrySystemInfoSyscall = NULL;
}