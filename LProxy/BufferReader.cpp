#include "BufferReader.h"

BufferReader::BufferReader(const char* InData, int Count)
	: BufferArchive(Count)
	, InternalData(InData)
{

}

BufferReader::~BufferReader()
{

}

void BufferReader::Serialize(void* Buffer, int Count)
{
	if (Buffer == nullptr) {
		return;
	}

	if (Offset + Count > BufferSize) {
		return;
	}

	std::memcpy(Buffer, InternalData + Offset, Count * sizeof(char));

	Offset += Count;
}
