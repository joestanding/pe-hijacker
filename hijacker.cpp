#include "hijacker.h"

PEHijacker::PEHijacker() {

}

PEHijacker::~PEHijacker() {

}

void PEHijacker::setHijackMode(int mode) {
	this->mode = mode;
}

int PEHijacker::loadPE(char * path) {
	std::ifstream peHandle;
	size_t peSize;
	unsigned char * peBuffer;

	peHandle.open(path, std::ios::binary);

	if (!peHandle.is_open()) {
		return -1;
	}

	peHandle.seekg(0, std::ios::end);
	peSize = peHandle.tellg();
	peHandle.seekg(0, std::ios::beg);

	peBuffer = new unsigned char[peSize];
	peHandle.read((char*)peBuffer, peSize);

	PIMAGE_DOS_HEADER peDosHeader = (PIMAGE_DOS_HEADER)peBuffer;
	PIMAGE_NT_HEADERS peNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)peDosHeader + peDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER peFileHeader = (PIMAGE_FILE_HEADER)&peNtHeaders->FileHeader;
	PIMAGE_OPTIONAL_HEADER peOptHeader = (PIMAGE_OPTIONAL_HEADER)&peNtHeaders->OptionalHeader;
	PIMAGE_SECTION_HEADER * peSecHeaders = new PIMAGE_SECTION_HEADER[peFileHeader->NumberOfSections];
	for (int i = 0; i < peFileHeader->NumberOfSections; i++)
		peSecHeaders[i] = (PIMAGE_SECTION_HEADER)((BYTE*)peNtHeaders + sizeof(IMAGE_NT_HEADERS) + (i) * sizeof(IMAGE_SECTION_HEADER));
	
	printf("---------------------------\n");
	printf(" File Header\n");
	printf("---------------------------\n");
	printf("  Number of Sections: %d\n", (int)peFileHeader->NumberOfSections);
	printf("  Number of Symbols: %d\n", (int)peFileHeader->NumberOfSymbols);
	printf("  Timestamp: %d\n", (int)peFileHeader->TimeDateStamp);
	printf("\n");
	printf("---------------------------\n");
	printf(" Optional Header\n");
	printf("---------------------------\n");
	printf("  Entry Point: %08x\n", peOptHeader->AddressOfEntryPoint);
	printf("\n");
	for (int i = 0; i < peFileHeader->NumberOfSections; i++) {
		printf("---------------------------\n");
		printf(" Section: %s\n", peSecHeaders[i]->Name);
		printf("---------------------------\n");
		printf("  Relative Virtual Address: %08x\n", peSecHeaders[i]->VirtualAddress);
		printf("  Virtual Size: %d (%08x)\n", peSecHeaders[i]->Misc.VirtualSize, peSecHeaders[i]->Misc.VirtualSize);
		printf("\n");
	}

	this->peBuffer = peBuffer;

	return ERROR_SUCCESS;
}