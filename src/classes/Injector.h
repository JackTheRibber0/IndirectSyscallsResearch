/*
 * Copyright (c) 2026 JackTheRibber0 - https://github.com/JackTheRibber0
 * Licensed under the Apache License, Version 2.0
 *
 * LEGAL DISCLAIMER:
 * This C++ source code and the resulting binary are intended strictly for
 * educational purposes, academic research, and authorized Red Team operations.
 * The author assumes no liability for unauthorized or malicious use.
 */

#pragma once

#include <Windows.h>
#include <string>

#include "Miscellaneous.h"

namespace injection
{
	class Injector
	{
	public:
		Injector() = default;
		~Injector() = default;

		BOOL inject(const PBYTE code, SIZE_T codeLen, const std::string& procName = "", const DWORD procId = 0, const bool bUseAPC = false) const; // facade-like func

	private:
		/*																			*/
		/****************************************************************************/
		/*   This function identified process ID by its application name			*/
		/*   Enumerates and checks all presented processes							*/
		/****************************************************************************/
		/*																			*/
		DWORD findCapableTarget(const std::string& procName) const;
	};
}