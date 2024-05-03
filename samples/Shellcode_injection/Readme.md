# Shellcode Injection Project

This project contains an example of a payload injection script that will inject meterpreter inside a notepad.exe running process

- Find target process
- XOR (decrypt) the encoded meterpreter payload
- Inject the meterpreter payload into the notepad.exe process
- CreateRemoteThread into this meterpreter injected

Until now, only behavioral detection can detect the payload (thanks to the xor !)

The problem is either AV detects the **pattern** of the meterpreter https OR it detects the payload in memory (Don't think so since when I deactivate, run the payload, and then perform a quick scan, it does not detect it !)

as I said, it does not detect the payload in memor !!!!! YOUPI !!
but it detect the initial connection of the meterpreter (with a staged payload ...)


Now I used a stageless apyload, it is not directly detected by after several seconds it got detected ... (behavior meterpreter)

we have to inject on "msedge.exe" or "scvhost.exe" to be stealthy !! 