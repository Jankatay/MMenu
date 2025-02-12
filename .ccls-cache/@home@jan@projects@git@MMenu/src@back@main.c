#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* error status */
enum ErrorStatus {
	success,
	errSyntax,
	errOther
};
extern enum ErrorStatus errStatus;
extern enum ErrorStatus getLexerStatus();
extern int getOutput(const char*);

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
