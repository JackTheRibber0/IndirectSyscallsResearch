; Copyright (c) 2026 JackTheRibber0 - https://github.com/JackTheRibber0
; Licensed under the Apache License, Version 2.0
;
; LEGAL DISCLAIMER:
; This Assembly source code and the resulting binary are intended strictly for
; educational purposes, academic research, and authorized Red Team operations.
; The author assumes no liability for unauthorized or malicious use.

.data 

EXTERN NtOpenProcSSN:DWORD
EXTERN NtWaitForSingleObjSSN:DWORD

EXTERN NtAllocVirtualMemSSN:DWORD
EXTERN NtProtectVirtualMemSSN:DWORD
EXTERN NtWriteVirtualMemSSN:DWORD

EXTERN NtCreateThreadExSSN:DWORD
EXTERN NtCloseSSN:DWORD
EXTERN NtQueueSSN:DWORD
EXTERN NtQuerrySystemInfoSSN:DWORD


EXTERN NtOpenProcSyscall:QWORD
EXTERN NtWaitForSingleObjSyscall:QWORD

EXTERN NtWriteVirtualMemSyscall:QWORD
EXTERN NtProtectVirtualMemSyscall:QWORD
EXTERN NtAllocVirtualMemSysscall:QWORD

EXTERN NtCreateThreadExSyscall:QWORD
EXTERN NtCloseSyscall:QWORD
EXTERN NtQueueSyscall:QWORD
EXTERN NtQuerrySystemInfoSyscall:QWORD


.code

NtOpenProcess proc
		mov r10, rcx
		mov eax, NtOpenProcSSN       
		jmp qword ptr [NtOpenProcSyscall]
		ret
NtOpenProcess endp

NtAllocateVirtualMemory proc
		mov r10, rcx
		mov eax, NtAllocVirtualMemSSN       
		jmp qword ptr [NtAllocVirtualMemSysscall]
		ret
NtAllocateVirtualMemory endp

NtWriteVirtualMemory proc
		mov r10, rcx
		mov eax, NtWriteVirtualMemSSN       
		jmp qword ptr [NtWriteVirtualMemSyscall]
		ret
NtWriteVirtualMemory endp

NtProtectVirtualMemory proc
		mov r10, rcx
		mov eax, NtProtectVirtualMemSSN       
		jmp qword ptr [NtProtectVirtualMemSyscall]
		ret
NtProtectVirtualMemory endp
		
NtCreateThreadEx proc
		mov r10, rcx
		mov eax, NtCreateThreadExSSN       
		jmp qword ptr [NtCreateThreadExSyscall]
		ret        
NtCreateThreadEx endp

NtWaitForSingleObject proc
		mov r10, rcx
		mov eax, NtWaitForSingleObjSSN       
		jmp qword ptr [NtWaitForSingleObjSyscall]
		ret
NtWaitForSingleObject endp

NtClose proc
		mov r10, rcx
		mov eax, NtCloseSSN       
		jmp qword ptr [NtCloseSyscall]
		ret
NtClose endp

NtQueueApcThread proc
		mov r10, rcx
		mov eax, NtQueueSSN
		jmp qword ptr [NtQueueSyscall]
		ret
NtQueueApcThread endp

NtQuerySystemInformation proc
		mov r10, rcx
		mov eax, NtQuerrySystemInfoSSN
		jmp qword ptr [NtQuerrySystemInfoSyscall]
		ret
NtQuerySystemInformation endp

end