/* Calculates hex/dec/bin math */
%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int yylex(void);
void yyerror(const char* msg);
int xtoi(const char* targetNum);
int btoi(const char* targetNum);
int getOutput(const char* str);

/* lexer functions */
extern void startLexer(const char* target);
extern void stopLexer();

/* error status */
enum ErrorStatus {
	success,
	errSyntax,
	errOther
};
extern enum ErrorStatus errStatus;
%}

/* tokens */
%token NUM
%token ADD SUB MUL DIV
%token OPENP CLOSEP
%token EOL


/* BNF Grammer, modified version of the example from o'reilly flex and bison book */
%%
calculation: calculation expression EOL { return $2; }
|
;

expression: term 
| expression ADD term 		{ $$ = $1+$3; }
| expression SUB term 		{ $$ = $1-$3; }
;

term: factor
| term MUL factor 		{ $$ = $1*$3; }
| term DIV factor			{ $$ = $1/$3; }
;

factor: NUM
| OPENP expression CLOSEP { $$ = $2; }
;
%%

#define BUFSIZE 255

/* Call this function with an input like 5+5*0xA and get the result in int */
int getOutput(const char* str) {
	char* usrInput = calloc(BUFSIZE, sizeof(char));
	usrInput[0] = '\0';
	strcat(usrInput, str);
	strcat(usrInput, "\n");
	startLexer(usrInput);
	int res = yyparse();
	stopLexer();	
	return res;
}

void yyerror(const char* msg) {
// nothing, user is responsible using 
}

int xtoi(const char* targetNum) {
	return strtol(targetNum, NULL, 16);
}

int btoi(const char* targetNum) {
	/* assume positive */
	char buf[BUFSIZE] = "+";
	
	/* if not positive, change to negative. Otherwise just concatonate normally. */
	if( targetNum[0] == '-' ) {
		strcat(buf, targetNum+3);
		buf[0] = '-';
	} else {
		strcat(buf, targetNum+2);
	}

	return strtol(buf, NULL, 2);
}

