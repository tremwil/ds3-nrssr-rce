#pragma once
#ifndef _PROTOFIELD_H
#define _PROTOFIELD_H

#include <inttypes.h>
#include <type_traits>
#include <vector>

#define PROTO_PARSE_INVALID 0

enum class ProtoFieldType
{
	Varint = 0,
	Fixed64 = 1,
	LengthDelim = 2,
	// Start Group not implemented
	// End Group not implemented
	Fixed32 = 5
};

// Implements every kind of Protobuf field (except startgroup/endgroup which aren't relevant to us)
struct ProtoField
{
	// Helper methods to read and write varints to/from buffers

	static size_t WriteU64Varint(uint64_t num, std::vector<uint8_t>& buff)
	{
		size_t nWritten = 1;
		while (num > 0x7F)
		{
			buff.push_back((num & 0x7F) | 0x80);
			num >>= 7;
			nWritten++;
		}
		buff.push_back(num);
		return nWritten;
	}

	// Read a 64-bit varint from a buffer, returning the number of bytes read.
	// If we tried to read more bytes than what is available, we return PROTO_PARSE_INVALID.
	static uint64_t ReadU64Varint(const uint8_t* buff, size_t size, int pos, size_t& nRead)
	{
		uint64_t num = 0, offset = 0;
		nRead = 0;
		while (pos + nRead < size)
		{
			num |= ((uint64_t)buff[pos + nRead] & 0x7F) << offset;
			offset += 7;
			if ((buff[pos + nRead++] & 0x80) == 0) break;
		}
		if (pos + nRead > size) nRead = PROTO_PARSE_INVALID;
		return num;
	}

	// The type of this ProtoField.
	ProtoFieldType type;
	// The numeric data it contains (if it has a numeric type)
	uint64_t numData;
	// The length-delimited data it contains (if it has type LengthDelim)
	std::vector<uint8_t> byteData;

	// Default constructor (0 varint)
	ProtoField() : type(ProtoFieldType::Varint), numData(0) { }

	// Default constructor, given field type
	ProtoField(ProtoFieldType type) : type(type), numData(0) { }

	// Construct from numeric type (Varint, Fixed64, Fixed32)
	template<typename TNum, std::enable_if_t<std::is_arithmetic_v<TNum>, bool> = true>
	ProtoField(TNum number, bool fixed = false)
	{
		uint64_t unum = 0;
		*(TNum*)&unum = number;
		if (fixed == false)
		{
			numData = std::is_unsigned<TNum>::value ? unum : (unum << 1) | (unum >> (8*sizeof(TNum) - 1));
			type = ProtoFieldType::Varint;
		}
		else
		{
			numData = unum;
			type = (sizeof(TNum) == 4) ? ProtoFieldType::Fixed32 : ProtoFieldType::Fixed64;
		}
	}

	// Construct from a byte array (length delim)
	ProtoField(const uint8_t* buff, size_t size) : type(ProtoFieldType::LengthDelim), byteData(buff, buff + size), numData(0) { }

	// Construct from an std::vector of bytes
	ProtoField(const std::vector<uint8_t>& buff) : type(ProtoFieldType::LengthDelim), byteData(buff.begin(), buff.end()), numData(0) { }

	// Construct from a utf-8 string (length delim)
	ProtoField(const std::string str) : type(ProtoFieldType::LengthDelim), byteData(str.begin(), str.end()), numData(0) { }

	// Construct from a utf-8 string (length delim)
	ProtoField(const char* str) : ProtoField(std::string(str)) { }

	ProtoField Copy() const
	{
		ProtoField f;
		f.type = type;
		f.numData = numData;
		f.byteData = std::vector<uint8_t>(byteData);
	}

	// Get the value of the numeric type in a certain format.
	template<typename TNum, std::enable_if_t<std::is_arithmetic_v<TNum>, bool> = true>
	TNum Value()
	{	
		// Handle zigzag encoding for signed varints
		uint64_t snum = numData;
		if (type == ProtoFieldType::Varint)
			snum = std::is_unsigned<TNum>::value ? numData : (numData & 1) << (8*sizeof(TNum) - 1) | (numData >> 1);
		return *(TNum*)&snum;
	}

	// Set the value of the numeric type in a certain format.
	template<typename TNum, std::enable_if_t<std::is_arithmetic_v<TNum>, bool> = true>
	void SetValue(TNum number)
	{	
		// Handle zigzag encoding for signed varints
		uint64_t unum = 0;
		*(TNum*)&unum = number;
		if (type == ProtoFieldType::Varint)
			numData = std::is_unsigned<TNum>::value ? unum : (unum << 1) | (unum >> (8*sizeof(TNum) - 1));
		else numData = unum;
	}

	// Write the field data at the end of a buffer. Return the number of bytes written.
	size_t Write(std::vector<uint8_t>& buff) const 
	{
		switch (type)
		{
		case ProtoFieldType::Varint:
			return WriteU64Varint(numData, buff);
			break;
		case ProtoFieldType::Fixed64:
		case ProtoFieldType::Fixed32:
		{	
			int s = (type == ProtoFieldType::Fixed64) ? 8 : 4;
			uint64_t n = numData;
			for (int i = 0; i < s; i++)
			{
				buff.push_back(n & 0xFF);
				n >>= 8;
			}
			return s;
			break;
		}
		case ProtoFieldType::LengthDelim:
		{
			size_t nWritten = WriteU64Varint(byteData.size(), buff);
			buff.insert(buff.end(), byteData.begin(), byteData.end());
			return nWritten + byteData.size();
		}
		default:
			return 0;
		}
	};

	// Read field data from a buffer at a specific position. Return the number of bytes read.
	// If the buffer contained invalid data, will return PROTO_PARSE_INVALID.
	size_t Read(const uint8_t* buff, size_t size, int pos)
	{
		size_t nRead = 0;
		numData = 0;
		byteData.clear();

		switch (type)
		{
		case ProtoFieldType::Varint:
			numData = ReadU64Varint(buff, size, pos, nRead);
			if (nRead == PROTO_PARSE_INVALID) return PROTO_PARSE_INVALID;
			break;
		case ProtoFieldType::Fixed64:
		case ProtoFieldType::Fixed32:
		{
			int s = (type == ProtoFieldType::Fixed64) ? 8 : 4, offset = 0;
			for (; nRead < s && pos + nRead < size; offset += 8)
				numData |= ((uint32_t)buff[pos + nRead++]) << offset;
			
			if (nRead != s) return PROTO_PARSE_INVALID;
			break;
		}
		case ProtoFieldType::LengthDelim:		
		{
			size_t lenSz = 0;
			uint64_t len = ReadU64Varint(buff, size, pos, lenSz);
			if (len == PROTO_PARSE_INVALID) return PROTO_PARSE_INVALID;

			pos += lenSz;
			// Handle packet with invalid size field
			if (pos + len > size) return PROTO_PARSE_INVALID;
			byteData = std::vector<uint8_t>(buff + pos, buff + pos + len);
			nRead = lenSz + len;
		}}
		return nRead;
	}
};

#endif