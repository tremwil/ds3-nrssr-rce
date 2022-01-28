# ds3-nrssr-rce
This repository contains proof of concept code and documentation for the most recent RCE exploit affecting FROM SOFTWARE games. While theoretically possible in other games, focus is on Dark Souls III as this is the game my research has been conducted on. If you wish to contribute implementations and documentation for other games, please do so in a separate repository and add your link to the table below using a pull request:


## Presence of the vulnerability in other games
| Game | Present? | "Exploitability" | Details/Implementation | Credit |
|-|:-:|-|-|-|
| DeS | Yes | RCE (probable)[^1] | | Unknown |
| DS1 PTDE | Yes | RCE (probable) | | Unknown |
| DS2 |  Yes | RCE (probable) | | Unknown |
| Bloodborne | Unknown | Unknown | | |
| DS3 |  Yes | **RCE (demonstrated)[^2]** | https://github.com/nrssr/ds3-nrssr-rce | nrssr |
| DS1R |  Yes | RCE (theoretical)[^3] | | Unknown |
| Sekiro | Yes | None (code never called) | | sfix |
| Elden Ring CNT | Yes | RCE (probable) | | sfix |

[^1]: Not definitely known whether the exploit can be sucessfully pulled off here.
[^2]: Exploit is known to be possible and an working implementation has been written.
[^3]: Exploit should be possible, but no working implementation has been written.

# Dispelling Misconceptions
Contrary to popular belief, this is NOT a peer-to-peer networking exploit. It is related to the matchmaking server and thus much more severe, since you do not need to partake in any multiplayer activity to be vulnerable due to another matchmaking server vulnerability. 

### TO BE CLEAR: A malicious attacker abusing this would have been able to reliably execute a payload of up to 1.3MiB[^4] of shellcode on every online player's machine within seconds. 
 
Due to the ridiculous severity of this exploit, its live demonstration was intentionally designed to spread the rumor that it was P2P related in order to hide it's true severity from malicious actors and hinder the discovery process for them, in the case that FROM SOFTWARE did not act quickly enough.

[^4]: For Dark Souls III Ver. 1.15. The maximum theoretical payload size depends on the stack layout and as such will vary by game and version.

# Table of Contents
TODO

# Exploit Summary
Improper bounds checking on a stack buffer and data size field during the parsing of `NRSessionSearchResult` matchmaking data allows an attacker to execute arbitrary code. The stack overflow allows one to overwrite the lower two bytes `vftable_ptr` of the `DLMemoryInputStream` object used internally by the stream reader, redirecting execution to carefully chosen neighboring code. Clever exploitation of the `DLMemoryInputStream` object's structure and data size field then allows one to achieve arbitrary code redirection. From there an ROP chain can be used to achieve arbitrary code execution.

# Distribution vectors
The distribution vectors are what make this particular RCE extremely serious (beyond already being an RCE). The exploit is transmitted through matchmaking push requests containing `NRSessionSearchResult` information. This means that the attacker can target anyone who joins their online session. In particular: 
- summons (`PushRequestSummonSign`)
- dark spirits invaders (`PushRequestAllowBreakInTarget`)
- players joining via covenant (`PushRequestVisit`)
- arena combattants (`PushRequestAcceptQuickMatch`)

This is already pretty bad, but the real potential is unlocked by the `RequestSendMessageToPlayers` request: 
```protobuf
message RequestSendMessageToPlayers { 
    repeated uint32 player_ids = 1; 
    required bytes push_message = 2;
}
```
The host uses this request to directly send the `PushRequestAllowBreakInTarget` push message to invaders so that they can obtain spawn coordinates and join their P2P session. That's it. That's the only way this request is used by the game. 
### Yet it allows any client to send arbitrary push messages to hundreds of thousands of specific players.
I cannot stress how horribly unsafe this is. Any player can basically impersonnate the matchmaking server. By using this request to send the exploit through a `PushRequestVisit`, any online player can be remotely targeted by the attacker as long as their player ID is known. The attacker can also send the exploit to the entire online playerbase very quickly by sending multiple requests, each containing a large slice of possible player IDs.

# The General Exploitation Tactic for All Games
While the RCE does not port exactly to every game, the core idea of the exploit which gives the attacker arbitrary code *redirection* is the same. If this can be achieved, it is very likely that a game-specific ROP chain can then be found. This "first step" uses the following vulnerabilities:

## Bug #1: No Bounds Check in Entry List Parser
Matchmaking push requests containing session join information store said information in a custom binary format which consists of a chain of length-deliminted data entries. Each entry consists of some kind of ID stored in a `uint32_t` followed by the size of the data entry as a `uint32_t` and the data itself. The game function responsible for copying the data of these entries blindly trusts the size field, which creates an out-of-bounds read. This can be abused by a malicious client by setting the size field to values like `0x7FFFFFFF`, causing the memory allocation to fail and the victim's game to crash. Later, this size is also passed to the constructor of a `DLMemoryInputSteam`, which is an instrumental part of the exploit. 

## Bug #2: Buffer Overrun in `NRSessionSearchResult` Parser
One of the entries in the data structure described above is a serialized `NRSessionSearchResult` object. The parser for this data first parses a list of properties. These properties can be 4 byte ints, 8 byte ints or null-terminated wide strings. This property list is followed by a null-terminated wide string `ホスト名`（host name）and some additional data not important for the exploit. Both this function and the property list parser use a fixed-size stack buffer to read strings, and in both cases no bounds check is performed on the buffer. Here is the game code responsible for copying the host name (produced using the Ghidra decompiler and then cleaned up): 
```cpp
size_t idx = 0;
wchar_t wchr = 0;
do {
  // read_wchar() function at vftable index 17 of DLEndianStreamReader
  wchr = stream_reader->read_wchar();
  player_name_buff[idx] = wchr;
  idx++;
} while (wchr != 0);
```
This leads to a buffer overrun exploit, allowing the attacker to corrupt the stack. 

## Paving the way for the ROP chain
To achieve arbitrary code redirection, we use this and the memory layout of a `DLMemoryInputStream` object instantiated on the stack by the function calling the parser, which is used internally by the stream reader:
```c
struct DLMemoryInputStream {
    uintptr_t* vftable_ptr; // Offset 0
    size_t data_size;       // Offset 4 (32bit) / 8 (64bit)
    uint8_t* data_buffer;   // Offset 8 (32bit) / 16 (64bit)
    // Entries after the buffer are not important for the exploit
}
```
Since we control the `data_size` field (Bug #1), it can be set to the stack memory address of the `data_buffer` field. This will succeed provided the address is constant and not too large (DS3 satisfies those requirements). Since the compiler places the stack buffer at the top of the frame, the attacker can then use Bug #2 to overwrite the lower two bytes of the `DLMemoryInputStream`'s `vftable_ptr`. Hence when the next character is read by the `DLEndianStreamReader`, it will call the `DLMemoryInputStream` internally and code will be redirected. The 2 bytes give enough leeway to jump to a function of the `DLEndianStreamReader` (TODO: specify vftable index) which is a wrapper for a function in its second virtual table. In a 64-bit process (i.e. Dark Souls III), the following instructions would be executed:
```nasm
MOV       RCX,qword ptr [RCX + 0x8]
MOV       RAX,qword ptr [RCX]
JMP       qword ptr [RAX + 0x40]
```
Since `RCX` is a pointer to the `DLMemoryInputStream` object, the first instruction writes the `data_size` field, which has been set to a stack address pointing to the `data_buffer` field by the attacker using Bug #1, into `RCX`. The two next instructions will thus redirect execution to the memory address the attacker has written at offset `0x40` in the data buffer. Arbitrary code redirection has now been achieved! From there the attacker can set up an ROP chain to copy their payload in a suitable memory region and execute it.
