# Indirect Windows System Calls Research
# Legal Disclaimer
Educational and Research Purposes Only
This software is provided strictly for academic research, educational purposes, and authorized security testing. 
**Limitation of Liability**
The author(s) of this project do not promote, encourage, support, or assume any responsibility for any illegal, malicious, or unauthorized use of this software. 
It is the end user's sole responsibility to obey all applicable local, state, and federal laws.
**Authorized Use**
By downloading, compiling, or using this software, you agree that you will only use it against systems, networks, and infrastructure for which you have explicit, legally documented permission to test.
**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.**

---

## Abstract
This repository contains a Proof of Concept (PoC) demonstrating advanced Windows API unhooking and evasion techniques using Indirect System Calls via the Tartarus Gate pattern. The project, written in C++ and x64 Assembly, dynamically resolves System Service Numbers (SSNs) and syscall pointers directly from memory. By doing so, it bypasses standard user-mode API hooking deployed by modern Endpoint Detection and Response (EDR) and Anti-Virus (AV) solutions. To further hinder static analysis, the execution payload and critical NTAPI function names are encrypted using AES-256.

---

## 1. Theoretical Background

### 1.1 The Evolution of User-Mode Hooking
Modern EDR solutions heavily rely on user-mode API hooking to monitor process behavior. By injecting their own dynamic link libraries (DLLs) into newly created processes, EDRs can overwrite the initial bytes of critical functions inside `ntdll.dll` (such as `NtAllocateVirtualMemory` or `NtCreateThreadEx`) with a `JMP` instruction. This redirects execution flow to the EDR's inspection engine before the system call transitions into the kernel. If the parameters are deemed malicious, the action is blocked.

### 1.2 Direct vs. Indirect System Calls
To bypass user-mode hooks, offensive researchers developed **Direct System Calls**. This technique involves hardcoding or dynamically resolving the System Service Number (SSN) and executing the `syscall` instruction directly from the payload's memory space, entirely bypassing `ntdll.dll`. 

However, Direct Syscalls introduced a new forensic artifact: the return address. When a direct syscall transitions back from kernel mode (Ring 0) to user mode (Ring 3), the Call Stack shows that the execution originated from unbacked, anomalous memory rather than the legitimate `ntdll.dll` memory space. Security products utilize Event Tracing for Windows (ETWti) to monitor these anomalous kernel transitions.

**Indirect System Calls** resolve this artifact. Instead of executing the `syscall` instruction from the payload's memory, the program dynamically resolves the SSN, prepares the CPU registers, and executes a `JMP` instruction pointing to a legitimate `syscall; ret` gadget located natively inside the `ntdll.dll` memory space. This ensures the Call Stack appears completely legitimate to kernel-level telemetry.

### 1.3 The Tartarus Gate Methodology
Dynamic SSN resolution techniques have evolved in response to EDR countermeasures:
*   **Hell's Gate:** Reads the `ntdll.dll` Export Address Table (EAT) from disk or memory to find clean syscall stubs. It fails if the EDR has hooked the specific function being queried.
*   **Halo's Gate:** An improvement that inspects neighboring syscall stubs in memory (checking functions immediately above or below the hooked function) to calculate the target SSN based on standard offset patterns.
*   **Tartarus Gate:** A further refinement utilized in this project. It handles edge cases where EDRs place hooks deeper into the stub or utilize complex `JMP` chains, allowing for highly rugged and reliable dynamic SSN and pointer evaluation even in heavily monitored environments.

---

## 2. Architecture & Project Structure

The project is modularized into core components designed for both standalone execution and modular integration:

* **`main.cpp`**
  The primary entry point for the standalone executable. Orchestrates the payload decryption, syscall resolution, and injection phases.
* **`NativeBridge.h`**
  A facade module that exports the `ExecuteNativeInjectionPipeline` function when the project is compiled as a Dynamic Link Library (`.dll`), enabling Unmanaged-to-Managed (P/Invoke) interoperability for C#/.NET Command and Control (C2) agents.
* **`Miscelaneous.h`**
  The structural backbone containing custom Windows internal definitions, undocumented NT structures, function prototype overrides, and Resource Acquisition Is Initialization (RAII) wrappers.
* **`Decryptor.h`**
  A standalone cryptography class handling AES encryption and decryption operations for both the shellcode and the protected NTAPI strings.
* **`NtResolver.h`**
  The dynamic resolution engine that implements the Tartarus Gate technique to locate safe SSNs and syscall pointers.
* **`Injector.h`**
  Handles target process acquisition, memory allocation, payload injection, and execution.
* **`calls.asm`** 
  Contains the low-level x64 Assembly instructions to safely execute the indirect system calls dynamically resolved by `NtResolver`.

---

## 3. Component Deep Dive

### 3.1 main.cpp: Orchestration and Entry Point
The `main.cpp` file serves as the primary execution harness for the PoC.
1. **Payload Decryption:** The executable embeds an AES-encrypted shellcode payload. It initializes the `Aes256Decryptor` with the required cryptographic keys and Initialization Vector (IV) to decrypt the payload dynamically into a memory buffer (`std::unique_ptr<UCHAR[]>`), ensuring the decrypted execution logic never touches the disk.
2. **System Call Resolution:** It instantiates the `NtResolver` and invokes `resolveNativeAPICalls()`, which begins the Tartarus Gate sequence to map `ntdll.dll` and extract the unhooked SSNs and memory pointers required for the injection phase.
3. **Target Selection & Injection:** The program prompts the user via standard input for a target process name (e.g., `msedge.exe`). It then passes the decrypted payload and the target process string to the `Injector` class.

### 3.2 calls.asm: The Execution Stubs (Indirect Syscalls)
The `calls.asm` file handles the transition from Ring 3 to Ring 0.
1. **Global Variable Integration:** The assembly file imports `EXTERN` global variables (SSNs as `DWORD` and Pointers as `QWORD`) populated by the C++ `NtResolver` class.
2. **x64 Syscall Convention:** Each procedure follows the standard Windows x64 calling convention for system calls by moving the first argument from `rcx` to `r10` and loading the dynamically resolved SSN into the `eax` register.
3. **Indirect Execution (The Evasion):** The stub executes a `jmp` instruction targeting the dynamically resolved memory address (`jmp qword ptr [Nt[Name]Syscall]`), ensuring the Call Stack originates from `ntdll.dll`.

### 3.3 Decryptor.h: Cryptographic Evasion Engine
The `Decryptor.h` component provides a custom RAII wrapper (`Aes256Decryptor`) around the statically linked **OpenSSL (EVP API)** library. 
* **Memory-Safe Decryption:** Provides methods to securely decrypt byte vectors into dynamically allocated buffers, ensuring decrypted artifacts are strictly managed in memory.
* **Static Linking:** Relies on `OPENSSL_STATIC` to bundle the cryptographic routines directly into the final binary, avoiding suspicious external library dependencies at runtime.

### 3.4 Miscelaneous.h: Architecture & Memory Safety
Because the project bypasses standard Windows API headers, it manually defines the undocumented structures required for direct kernel interaction.
1. **Native NTAPI Overrides (`extern "C"`):** Manually defines function signatures for undocumented system calls (e.g., `NtAllocateVirtualMemory`), linking to the custom Assembly stubs.
2. **RAII Handle Management (`ScopedHandle`):** A custom C++ wrapper for Windows `HANDLE` objects ensuring handles are automatically closed via `NtClose` to prevent memory leaks.

### 3.5 NtResolver.h: Dynamic Resolution & String Evasion
The `NtResolver` class ensures the payload can interact with the Windows kernel without triggering user-land hooks.
1. **NTDLL Fetching (`fetchNativeAPIDLL`):** Fetches the base address of `ntdll.dll` and parses its Export Address Table (EAT) in memory.
2. **Tartarus Gate Implementation (`staticResolveNAPICalls`):** Resolves SSNs and memory pointers by inspecting neighboring syscall stubs if the target function is hooked or altered by an EDR.
3. **AES Encrypted Stack Strings (OPSEC):** Sensitive NTAPI strings are stored as AES-encrypted `std::vector<uint8_t>` byte arrays, preventing static string analyzers from identifying the executable's capabilities.

### 3.6 Injector.h: Execution & Evasion Workflow
The injection routine utilizes a staged RW-to-RX memory transition to avoid suspicious `PAGE_EXECUTE_READWRITE` (RWX) memory allocations.
1. **Target Acquisition (`NtOpenProcess`):** Resolves the target Process ID (PID) and requests a handle. 
2. **Memory Allocation (`NtAllocateVirtualMemory`):** Memory is reserved in the remote process with `PAGE_READWRITE` (RW) permissions.
3. **Payload Injection (`NtWriteVirtualMemory`):** The decrypted shellcode is written across the process boundary.
4. **Memory Protection Alteration (`NtProtectVirtualMemory`):** Memory protection is dynamically flipped from `PAGE_READWRITE` to `PAGE_EXECUTE_READ` (RX).
5. **Thread Creation (`NtCreateThreadEx`):** A remote thread is spawned within the target process. Bypassing hooks on this specific call is critical to avoid immediate termination.
6. **Thread Synchronization (`NtWaitForSingleObject`):** Safely waits for the remote thread to conclude execution.

---

## 4. Detection Efficacy and Current Limitations

While this Proof of Concept successfully demonstrates the mechanics of Indirect System Calls and effectively evades basic user-mode telemetry, its current implementation has notable detection limitations against full-spectrum Endpoint Protection Platforms (EPP) and aggressive heuristic scanners.

### 4.1 Runtime Detection (Execution Phase)
The execution chain successfully bypasses standard Microsoft Defender runtime telemetry. However, advanced third-party antivirus solutions reliably detect and interrupt the injection sequence at runtime. 

The primary point of failure is the invocation of `NtCreateThreadEx`. Even when executed via an unhooked indirect syscall (which hides the API call from user-land hooks), the Windows kernel still fires the `PspCreateThreadNotifyRoutine` callback internally. This kernel-level notification alerts the security product to anomalous cross-process thread creation originating from our executable, leading to immediate process termination.

### 4.2 Static Analysis (Entropy and Heuristics)
From a static analysis perspective, the executable maintains a low profile against most traditional signature-based scanners due to the absence of recognizable plaintext NTAPI strings. However, aggressive heuristic engines—specifically Malwarebytes—successfully flag the binary as a Potentially Unwanted Program (PUP) or generic threat. This static detection is triggered by entropy analysis; the binary contains exceptionally large, contiguous blocks of high-entropy data (the AES-encrypted shellcode payload alongside the stack of encrypted NTAPI function names), which is a common indicator of packed or obfuscated code.

---

## 5. Future Work: The Shift to Windows Thread Pool Injection

To address the OPSEC limitations outlined in Section 4—specifically the runtime detection of remote thread creation—future updates to this research will explore **Windows Thread Pool Injection**. 

Process injection techniques have evolved rapidly in recent years. Red teams and advanced threat actors recognize that security solutions heavily monitor thread creation across process boundaries. The mere act of spawning a thread in a remote process (especially one targeting a newly allocated, executable memory region) generates significant behavioral anomalies. 

### 5.1 Exploiting Native Worker Threads
Rather than creating a highly suspicious new thread via `NtCreateThreadEx`, modern offensive tradecraft leverages the native Windows Thread Pool architecture. The Windows OS maintains a pool of worker threads within every process to handle asynchronous callbacks, timers, and IO operations. 

By manipulating these internal thread pool structures (utilizing APIs like `TpAllocWork`, `TpPostWork`, or the underlying undocumented system calls), an attacker can queue a malicious asynchronous procedure call (APC) or work item. An already-existing, legitimate worker thread will eventually dequeue and execute the injected payload.

This methodology introduces severe challenges for defensive telemetry:
1.  **No Thread Creation Callback:** It bypasses `PspCreateThreadNotifyRoutine` entirely because no new threads are spawned; the payload rides on threads created during the target's initial startup phase.
2.  **Legitimate Execution Context:** The payload is executed by a thread that belongs to the operating system's native pool, drastically reducing the behavioral anomaly score.
3.  **Complex Call Stacks:** Thread pool execution results in asynchronous, fragmented call stacks that complicate forensic analysis and heuristic attribution.

The next phase of this project will refactor the `Injector.h` component, integrating Thread Pool manipulation with the existing Tartarus Gate resolution engine to demonstrate a fully stealth, thread-less injection pipeline.

---
*End of Document*
