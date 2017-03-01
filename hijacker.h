#pragma once
#include <iostream>
#include <fstream>
#include <Windows.h>

class PEHijacker {
private:
	char * path;
	int mode;
	unsigned char * peBuffer;

public:
	PEHijacker();
	~PEHijacker();
	void setHijackMode(int);
	int loadPE(char * path);
};