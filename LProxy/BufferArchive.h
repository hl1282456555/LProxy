#ifndef BUFFER_ARCHIVE_H
#define BUFFER_ARCHIVE_H

#include <vector>

class BufferArchive
{
public:
	BufferArchive(int InBufferSize, int InOffset = 0);

	virtual ~BufferArchive();

	virtual inline bool IsReading() = 0;

	virtual inline int GetOffset() { return Offset; }

	virtual void Serialize(void* Buffer, int Count) = 0;

protected:
	int BufferSize;
	int Offset;
};


#endif // !BUFFER_ARCHIVE_H
