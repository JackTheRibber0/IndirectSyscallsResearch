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

#include "NativeBridge.h"

BOOL APIENTRY ExecuteNativeInjectionPipeline(int procId, unsigned char* code, int codeLen)
{
    resolver::NtResolver ntResolver;
    ntResolver.resolveNativeAPICalls();

    injection::Injector injector;
    bool result = injector.inject((PBYTE)code, codeLen, "", procId);

    return result;
}
#endif