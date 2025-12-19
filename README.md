## strcrypt
Compile-time string encryption with forced secure patterns for C++17+
What is the problem?
#1 Strings

Plain strings in binaries are trivially extractable with strings.exe, IDA, or any hex editor
Attackers can signature scan for known strings to locate critical code sections
API names, registry keys, and config values expose your program's functionality

#2 Most string encryptors

Decrypt to static memory that persists forever where memory dumps reveal everything
Return pointers that developers accidentally store, leaking plaintext
Allow implicit conversions that create dangling references
Use weak single-stage XOR that's trivially reversible
Lack integrity verification, tampered ciphertext decrypts to garbage silently

Why this strcrypt?
Features

7-stage encryption: XOR → ADD → ROL → XOR → SUB → ROR → XOR with position-dependent keys
Forced scoped decryption: Plaintext only exists inside callback, impossible to leak
SecureZeroMemory wipe: Optimizer-proof memory clearing on Windows
SipHash-2-4 comparison: Compare strings without ever decrypting (constant-time)
Integrity verification: Detects binary tampering, returns invalid on mismatch
Per-build polymorphism: Keys derived from __TIME__, __DATE__, __FILE__, __LINE__, __COUNTER__
No CRT dependency: Works in kernel drivers, shellcode, anywhere

Usage
```
#include "str.hpp"

e_use("secret string", {
    printf("%s\n", it);
});

ew_use("kernel32.dll", {
    LoadLibraryW(it);
});

e_call("hello", puts);

if (e_cmp(user_input, "password")) {
}

if (e_cmpw(dll_name, "ntdll.dll")) {
}
```

### API Reference

| Macro | Description |
|-------|-------------|
| `e_use(str, { code })` | Decrypt string, use as `it`, auto-wipe |
| `ew_use(str, { code })` | Wide string version |
| `e_call(str, fn)` | Shorthand for `e_use(str, { fn(it); })` |
| `ew_call(str, fn)` | Wide string version |
| `e_cmp(input, literal)` | Constant-time hash compare (no decrypt) |
| `e_cmpw(input, literal)` | Wide string version |

### How it works
```
Compile-time:
1. Generate unique keys from build metadata + __COUNTER__
2. Encrypt each byte: 7-stage transformation
3. Compute integrity hash of plaintext
4. Store encrypted blob + hash in .rdata

Runtime:
1. Decrypt to stack buffer inside callback
2. Verify integrity hash
3. Pass pointer to user code
4. SecureZeroMemory on scope exit

Requirements

C++17 or higher
MSVC, Clang, or GCC
Windows (for SecureZeroMemory) or Unix (fallback provided)

License
MIT
