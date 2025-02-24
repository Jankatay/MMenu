#ifndef WRAPPER_H
#define WRAPPER_H

#include <libqalculate/qalculate.h>
#include <cstring>
#include <string>

using namespace std;

extern "C" char* solve(char* equation) {
	new Calculator();
	char *res = (char*)malloc(255);
	string str = string(equation);
	string calculation = CALCULATOR->calculateAndPrint(str);
	strcpy(res, calculation.c_str());
	return res;
}

#endif
