#include "mmenu.h"

int main(int argc, char* argv[]) {
	initMMenu();

	char *question = "9999999999999991+9";
	char *buf = solve(question);
	printf("%s\n", buf);

	freeMMenu();
	return 0;
}
