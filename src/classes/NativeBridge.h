/*
 * Copyright (c) 2026 JackTheRibber0 - https://github.com/JackTheRibber0
 * Licensed under the Apache License, Version 2.0
 *
 * LEGAL DISCLAIMER:
 * This C++ source code and the resulting binary are intended strictly for
 * educational purposes, academic research, and authorized Red Team operations.
 * The author assumes no liability for unauthorized or malicious use.
 */

#ifdef _WINDLL

#include "Injector.h"
#include "NtResolver.h"

/*                                                        */
/**********************************************************/
/*   bridge class with facade-like function that allows   */
/*   to perform native shellcode injection calls from C#  */
/*   C2 agent code or other APPs. Packed as .dll.         */
/**********************************************************/
/*                                                        */
extern "C"
{
	DllExport BOOL APIENTRY ExecuteNativeInjectionPipeline(int procId, unsigned char* code, int codeLen);
}

#endif