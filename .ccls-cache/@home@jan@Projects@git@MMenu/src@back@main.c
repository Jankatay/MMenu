#include "mmenu.h"

int main(int argc, char* argv[]) {
	initMMenu();

	mpf_t res;
	mpf_init(res);
	getFinalOutput("0xFFFFFFFFFFFFFFFFFF*12x=4722366482869645213695", res);
	gmp_printf("%Ff\n", res);
	mpf_clear(res);

	freeMMenu();
	return 0;
}
