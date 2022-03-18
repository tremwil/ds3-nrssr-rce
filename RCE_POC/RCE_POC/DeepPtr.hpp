#pragma once
#ifndef _DEEP_PTR_H
#define _DEEP_PTR_H

#include <Windows.h>
#include <initializer_list>

inline uintptr_t GetDeepPtrAddr(uintptr_t* base, std::initializer_list<uintptr_t> offsets)
{
	for (uintptr_t o : offsets)
	{
		if ((uintptr_t)base < 0x10000 || IsBadReadPtr(base, sizeof(void*))) return NULL;
		base = (uintptr_t*)(*base + o);
	}
	return (uintptr_t)base;
}

template<typename TRet, typename TBase, typename ... TOffsets> TRet* AccessDeepPtr(TBase base, TOffsets... offsets)
{
	uintptr_t addr = GetDeepPtrAddr((uintptr_t*)base, { (uintptr_t)offsets... });
	return (addr < 0x10000 || IsBadReadPtr((void*)addr, sizeof(TRet))) ? NULL : (TRet*)addr;
}

#endif