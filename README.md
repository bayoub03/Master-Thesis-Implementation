# Repository Overview

This repository hosts the implementation of Ayoub's Master Thesis, which explores Malware Obfuscation and Evasion Techniques. The primary focus is on developing methods to bypass the CAPEv2 sandbox.

## Author

BOUHNINE Ayoub

## Repository Structure

The repository is organized as follows:

- **Custom Payloads:** Contains various custom payloads.
- **AVET Folder:** Hosts the AVET (AntiVirus Evasion Tool).
- **SysWhispers3 Folder:** Used for generating (or possibly statically embedding different payloads within AVET).

## Research Paper

The accompanying thesis paper is available for download in the [paper folder](./paper/thesis.pdf).

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

For xoring the payload we used ...
