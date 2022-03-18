#pragma once
#ifndef _FDPCLIENT_H
#define _FDPCLIENT_H

#include <stdint.h>
#include "DeepPtr.hpp"

// Reversed engineered FdpClient game class. Cut down to what is necessary for the PoC

class FdpClient
{
public:
	static const uintptr_t FDP_CLIENT_BASE = 0x14477FEE8;

	// Get a pointer to the FrpgRequestManager instance
	uintptr_t* RequestManager() const
	{
		return (uintptr_t*)this + 0xB;
	}

	// Get a pointer to the RPCSystemImpl game class instance
	uintptr_t* RPCSystemImpl() const
	{
		return *((uintptr_t**)this + 0xC);
	}

	// Get a pointer the game's FdpClient instance or a null pointer if it has not been initialized yet
	static FdpClient* Instance()
	{
		return AccessDeepPtr<FdpClient>(FDP_CLIENT_BASE, 0x8F0);
	}

	// Send a FRPG message to the matchmaking servers. 
	uint64_t SendFrpgPacket(uint32_t frpgMsgId, uint8_t* buffer, size_t size)
	{
		// We need to construct a ClientLib::RequestStatusForDefault object using the game's allocator.
		void* dlAllocator = ((void* (*)())0x141b496d0)();
		uint64_t* requestStatus = ((uint64_t * (*)(size_t, size_t, void*))0x141769a30)(0x30, 8, dlAllocator);

		auto requestStatusCtor = (void (*)(void*))0x141b54a50;
		requestStatusCtor(requestStatus);
		requestStatus[0] = 0x143a96de8; // Allocator vftable

		// Send the request

		auto rpcSystem = RPCSystemImpl();
		if (rpcSystem == 0) return 0;

		uintptr_t unk = 0;
		auto sendRawFrpgPacket = (uint64_t(*)(void*, uint32_t, void*, size_t, void*, void*, void*))0x141b52c60;
		return sendRawFrpgPacket(rpcSystem, frpgMsgId, buffer, size, requestStatus, RequestManager(), &unk);
	}
};

#endif