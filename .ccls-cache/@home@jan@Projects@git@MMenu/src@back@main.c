#include "mmenu.h"

int main(int argc, char* argv[]) {
	initMMenu();
	char res[32][64];
	const uint8_t nops[5] = {233, 135, 0, 0, 0};
	int len = codeToAsm(nops, res);
	for(int i = 0; i < len; i++) {
		printf("%s\n", res[i]);
	}
	freeMMenu();
	return 0;
}
