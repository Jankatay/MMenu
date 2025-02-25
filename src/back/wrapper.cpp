#ifndef WRAPPER_H
#define WRAPPER_H

#include <libqalculate/qalculate.h>
#include <cstring>
#include <string>

using namespace std;

extern "C" char* solve(char* equation) {
	new Calculator();
	char *res = (char*)malloc(255);
	MathStructure mstruct = CALCULATOR->calculate(equation);
	if(mstruct.isNumber()) {
		sprintf(res, "%d", mstruct.number().intValue());
	} else {
		strcpy(res, mstruct.eval().print().c_str());
	}
	return res;
}

#endif
