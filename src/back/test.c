#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main() {
	int res = getOutput("5+5*2-0xa");
	printf("%d\n", res);
	return 0;
}

