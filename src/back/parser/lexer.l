/* The lexer for calculator */
%{
/* Tokens and functions are declared in parser.y */
#include "parser.h"
extern int btoi(const char*);
extern int xtoi(const char*);
/* error status */
enum ErrorStatus {
	success,
	errSyntax,
	errOther
};
enum ErrorStatus errStatus;
%}

/* Uses regex to tokenize operations */
%%
"+" 			{ return ADD; }
"-" 			{ return SUB; }
"*" 			{ return MUL; }
"/" 			{ return DIV; } 
[0-9]+ 		{ yylval=atoi(yytext); return NUM; } /* atoi from stdlib   */
0x[0-9a-zA-Z]+ 	{ yylval=xtoi(yytext); return NUM; } /* xtoi from parser.y */
0b[01]+ 	{ yylval=btoi(yytext); return NUM; } /* btoi from parser.y */
[ \t] 		{ }
"\n" 			{ return EOL; }
. 				{ errStatus=errSyntax; }
""
%%

/* returns error status */
enum ErrorStatus getLexerStatus() {
	return errStatus;
}

void startLexer(const char* str) {
	yy_scan_string(str);
}

void stopLexer(void) {
	yy_delete_buffer(YY_CURRENT_BUFFER);
}
