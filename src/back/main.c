#include "mmenu.h"

int main(int argc, char* argv[]) {
	initMMenu();
	int res = getFinalOutput("\"mov eax, ebx;\" ");
	if(mstatus) {
		return 1;
	}
	printf("%d\n", res);
	freeMMenu();
	return 0;
}
