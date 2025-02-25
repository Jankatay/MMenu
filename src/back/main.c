#include "mmenu.h"

int replaceAsmWithCode(char* as) {
	char res[255] = "0x";
	char out[255] = "";
	as[strlen(as)-1] = '\0';
	asmToCode(as+1, out);
	strcpy(as, out);
	return strlen(out);
}

int main(int argc, char* argv[]) {
	printf("%s\n", solve("5x=555"));
	freeMMenu();
	return 0;
}
