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

The samples included in this repository use several evasion techniques:

- **Obfuscation:** A stageless Meterpreter x64 reverse HTTPS payload that employs a basic XOR encryption is used.
- **Dynamic API Loading:** Implements dynamic loading of APIs.
- **NTAPIs:** Uses dynamic loading of NTAPIs.
- **Evasion of API Hooks:** Employs Direct Syscalls for evading API hooks.

These techniques have been integrated by the author within the AVET framework available on this repo. For syscall generation, the tool **SysWhispers3** is used, available at: [SysWhispers3 on GitHub](https://github.com/klezVirus/SysWhispers3).

## Modification of the payload

The payload used is stageless Meterpreter x64 reverse HTTPS payload that employs a basic XOR encryption is used. This has to be replaced if you want to use your payload with the right IP address.

## Utils

For xoring the payload we used ...