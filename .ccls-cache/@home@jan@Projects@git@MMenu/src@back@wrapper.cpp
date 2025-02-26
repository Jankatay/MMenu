#ifndef WRAPPER_H
#define WRAPPER_H

#include <libqalculate/qalculate.h>
#include <gmp.h>
#include <cstring>
#include <string>
#include <iostream>

using namespace std;

extern "C" char* solve(char* equation) {
	char *res = (char*)malloc(255);
	new Calculator(); 
	MathStructure temp, mstruct = CALCULATOR->calculate(equation);
	PrintOptions op;
	op.min_exp = 30;
	// calculate 
	if( mstruct.isNumber() ) {
		strcpy(res, mstruct.print(op).c_str());
	} else if ( !mstruct.countChildren() ) {
		res = NULL;
	} else if ( mstruct.last().isNumber() ){
		strcpy(res, mstruct.last().print(op).c_str());
	} else {
		res = NULL;
	}
	return res;
}

#endif
