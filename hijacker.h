#pragma once

#include <iostream>
#include <fstream>
#include <Windows.h>

class PEHijacker {
private:
	unsigned char * peBuffer;
	size_t peSize;
	PIMAGE_DOS_HEADER peDosHeader;
	PIMAGE_NT_HEADERS  peNtHeaders;
	PIMAGE_FILE_HEADER  peFileHeader;
	PIMAGE_OPTIONAL_HEADER  peOptHeader;
	PIMAGE_SECTION_HEADER * peSecHeaders;
	unsigned char * shellcode;
	unsigned int shellcodeLength;
public:
	int ARCH_X86 = 1;
	int ARCH_X64 = 2;
	PEHijacker();
	int loadPE(char * pePath);
	int savePE(char * pePath);
	void hijack();
	void setArchitecture(int arch);
	void setShellcode(unsigned char * shellcode, unsigned int length);
	void setEntryPoint(DWORD address);
	void printFileHeader();
	void printOptionalHeader();
	void printSectionHeader(PIMAGE_SECTION_HEADER sectionHeader);
	DWORD getEntryAddress();
	DWORD getStartOfPadding(PIMAGE_SECTION_HEADER sectionHeader);
	DWORD getDataSize(PIMAGE_SECTION_HEADER sectionHeader);
	DWORD getPaddingSize(PIMAGE_SECTION_HEADER sectionHeader);
	PIMAGE_SECTION_HEADER getSectionHeader(char * sectionName);
};