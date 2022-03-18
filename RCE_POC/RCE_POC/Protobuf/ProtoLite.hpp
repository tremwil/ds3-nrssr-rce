#pragma once
#ifndef _PROTOLITE_H
#define _PROTOLITE_H


#include <string>
#include <map>
#include "ProtoField.hpp"

// A simple Protobuf message parser/serializer which handles most Proto2 constructs. 
class ProtoLiteMsg
{
private:
	std::map<uint64_t, std::vector<ProtoField>> mFields;

public:
	ProtoLiteMsg() { }

	// Create a deep copy of this proto lite message.
	void DeepCopy() const
	{
		ProtoLiteMsg msg;
		for (auto& kv : mFields)
		{
			msg.mFields[kv.first] = std::vector<ProtoField>();
			for (auto& field : kv.second)
				msg.mFields[kv.first].push_back(field.Copy());
		}
	}

	// Add a new field to this ProtoLite message. Returns true on success, false
	// if you tried to add an entry of different type to a repeated field.
	bool AddField(uint64_t id, ProtoField field)
	{	// Create the repeated field vector if not present
		if (mFields.count(id) == 0)
			mFields[id] = std::vector<ProtoField>();
		// Check if the type matches
		auto& v = mFields[id];
		if (v.size() != 0 && v[0].type != field.type) return false;
		// Add the field to the map
		v.push_back(field);
		return true;
	}

	// Replace a field in this ProtoLite message. Returns true on success, false
	// if you tried to replace a repeated field
	bool SetField(uint64_t id, ProtoField field)
	{
		if (mFields.count(id) == 0 || mFields[id].size() > 1) return false;
		mFields[id][0] = field;
		return true;
	}

	// Replace an entry in this ProtoLite message. Returns true on success, false
	// if the entry field type is not compatible or the index is out of bounds.
	bool SetEntry(uint64_t id, int index, ProtoField field)
	{
		if (mFields.count(id) == 0 || index >= mFields[id].size() || mFields[id][0].type != field.type) return false;
		mFields[id][index] = field;
		return true;
	}

	// Will completely delete a field, including all entries if it is repeated.
	// Returns true on success, false if the field does not exist.
	bool DeleteField(uint64_t id)
	{
		if (mFields.count(id) == 0) return false;
		mFields.erase(id);
		return true;
	}

	// Will delete a particular entry. Returns true on success, false if the entry does not exist.
	bool DeleteEntry(uint64_t id, int index)
	{
		if (mFields.count(id) == 0 || index >= mFields[id].size()) return false;
		mFields[id].erase(mFields[id].begin() + index);
		return true;
	}

	// Add an embedded message to this ProtoLite message. Returns true on success, false
	// if you tried to add an entry to a non length-delim field
	bool AddEmbeddedMsg(uint64_t id, ProtoLiteMsg& msg)
	{
		auto data = msg.Serialize();
		return AddField(id, ProtoField(data));
	}

	// Check if a field is present inside this message.
	bool HasField(uint64_t id)
	{
		return mFields.count(id) != 0;
	}

	// Return the number of entries for a given field ID.
	size_t GetNumEntries(uint64_t id)
	{
		return (mFields.count(id) == 0) ? 0 : mFields[id].size();
	}

	// Get all entries in a repeated field.
	std::vector<ProtoField> GetRepeatedField(uint64_t id)
	{
		return (mFields.count(id) == 0) ? std::vector<ProtoField>() : mFields[id];
	}

	// Return a specific entry in a potentially repeated field.
	ProtoField GetFieldEntry(uint64_t id, int index = 0)
	{
		return mFields[id][index];
	}

	// Get all fields present in this message. NOTE: Modifying this map modifies the message data!
	std::map<uint64_t, std::vector<ProtoField>> GetFields()
	{
		return mFields;
	}

	// Return a ProtoLite object created by interpreting a lenght delimited field as an embedded message.
	// Make sure the field is length-delimited before calling this!
	ProtoLiteMsg GetEmbeddedMsg(uint64_t id, int index = 0)
	{
		ProtoLiteMsg msg;
		ProtoField& f = mFields[id][index];
		return msg.Parse(&f.byteData[0], f.byteData.size()) ? msg : ProtoLiteMsg();
	}

	// Fill ProtoLite object by interpreting a lenght delimited field as an embedded message.
	// Returns true on success and false if the parsing failed.
	bool ParseEmbeddedMsg(uint64_t id, int index, ProtoLiteMsg& msgOut)
	{
		ProtoField& f = mFields[id][index];
		return msgOut.Parse(&f.byteData[0], f.byteData.size());
	}

	// Attempt to parse a Protobuf message from a byte buffer.
	bool Parse(const uint8_t* buff, size_t size)
	{
		mFields.clear();

		size_t pos = 0, nRead = 0;
		for (; pos < size; pos += nRead)
		{
			uint64_t rawId = ProtoField::ReadU64Varint(buff, size, pos, nRead);
			if (nRead == PROTO_PARSE_INVALID) return false;
			pos += nRead;

			ProtoField f(static_cast<ProtoFieldType>(rawId & 0x7));
			nRead = f.Read(buff, size, pos);
			if (nRead == PROTO_PARSE_INVALID) return false;
			AddField(rawId >> 3, f);
		}
		return pos == size;
	}

	// Serialize the Protobuf message.
	std::vector<uint8_t> Serialize() const
	{
		std::vector<uint8_t> buff;
		for (auto rf = mFields.begin(); rf != mFields.end(); rf++)
		{
			for (const auto& f : rf->second)
			{
				ProtoField::WriteU64Varint(rf->first << 3 | static_cast<uint64_t>(f.type), buff);
				f.Write(buff);
			}
		}
		return buff;
	}
};

#endif