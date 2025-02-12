#ifndef ENUMS_H
#define ENUMS_H

enum ErrorStatus {
	success,
	errSyntax,
	errOther
};
extern enum ErrorStatus getLexerStatus();

#endif
