#include "parser.h"
#include "enums.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* error status */
int main(int argc, char* argv[]) {
	if(argc != 2) {
		fprintf(stderr, "Usage: ./main <calculation string in quotes>\n", stderr);
		exit(EXIT_FAILURE);
	}

	int res = getOutput(argv[1]);
	if(getLexerStatus() != success) {
		fprintf(stderr, "Syntax error\n");
		exit(EXIT_FAILURE);
	}

	printf("%d\n", res);
	return 0;
}
