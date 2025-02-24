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
	char try[255] = "5/1.5";
	char out[255] = "";

	initMMenu();

	regplace(try, "\".*\"", replaceAsmWithCode, out);
	printf("%s\n=\t%s\n", out, solve(out));


	freeMMenu();
	return 0;
}
