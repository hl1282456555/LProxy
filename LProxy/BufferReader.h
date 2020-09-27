#ifndef BUFFER_READER_H
#define BUFFER_READER_H

#include "BufferArchive.h"

class BufferReader : public BufferArchive
{
public:

	BufferReader(const char* InData, int Count);

	virtual ~BufferReader();

	virtual bool IsReading() { return true; }

	virtual void Serialize(void* Buffer, int Count);

protected:
	const char* InternalData;
};


#endif // !BUFFER_READER_H
