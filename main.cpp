#include "main.h"
#include "hijacker.h"

int main(int argc, char * argv[]) {
	printf("PE Hijacker!\n\n");

	PEHijacker * hj = new PEHijacker();

	if (hj->loadPE("C:\\WINDOWS\\system32\\calc.exe") != ERROR_SUCCESS) {
		printf("Failed to load PE! GetLastError(): %d\n", GetLastError());
	}

	system("pause");
}