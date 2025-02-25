#include "mmenu.h"

int main(int argc, char* argv[]) {
	initMMenu();
	float res = getFinalOutput("5+5.5");
	printf("%f\n", res);
	freeMMenu();
	return 0;
}
