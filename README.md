# IPv4-Shellcode-Obfuscator

# Introduction
The IPv4 Shellcode Obfuscator / Deobfuscator transforms your shellcode into IPv4 Addresses

## Usage
Clone the repository to your local machine
Compile the code using a C compiler
Run the executable

### Example Compilation & Execution

```sh
# Clone the repository
git clone

# Navigate to project directory
cd IPv4-Shellcode-Obfuscator

# Adjust the shellcode as necessary.
It is currently set to run calc.exe

# Compile the code
gcc IPv4Encrypt.c -o IPv4Encrypt.exe
gcc IPv4Decrypt.c -o IPv4Decrypt.exe

# Run the executable
.\IPv4Encrypt.exe
.\IP4vDecrypt.exe
```

#### Note about the deobfuscator
The deobfuscator returns a `PBYTE` data type. This allows ease of implementation into other code bases. 
