#ifndef MMENU_H
#define MMENU_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
// dependencies
#include <capstone/capstone.h> 			
#include <keystone/keystone.h>


// Use this global mstatus for error checking
enum MMenuStatus {
	ERR_OK = 0,
	ERR_SYNTAX,  
	ERR_ASSEMBLE,
	ERR_DISASSEMBLE,
	ERR_CONVERSION,
	ERR_INIT,
	ERR_OTHER
};
extern enum MMenuStatus mstatus;
extern char* solve(char *equ);


/* initializing functions */

// Initialize status and global pointers for this library
// ERR_INIT
void initMMenu();

// Free all pointers made by initMMenu.
void freeMMenu();


/* convenient functions that just work right after initializing with no setup*/

// Get final output in a single function.
// ERR_SYNTAX ERR_CONVERSION ERR_OTHER.
int getFinalOutput(char *equ);


/* Converting data functions */

// Calculate numbers and solve for 'x' if given
// ERR_SYNTAX ERR_OTHER
int calculateNumbers(char *equ);

// Convert between hex and int
// ERR_CONVERSION ERR_OTHER 
int xtoi(char *hex);
char* itox(int num); // Free result when done

// between binary and int
// ERR_CONVERSION ERR_OTHER 
int btoi(char *bin);
char* itob(int num); // Free result when done

// between octagonal and int
// ERR_CONVERSION ERR_OTHER 
int otoi(char *oct);
char* itoo(int num); // Free result when done.


/* Assember and disassembler */

// disassemble x86_64 opcodes into res line by line. returns how many lines or -1 on error
// ERR_DISASSEMBLE
int codeToAsm(uint8_t *opcode, char res[32][64]);

// assemble x86_64 code into res as a string of opcodes. returns number of lines or -1 on error.
// ERR_ASSEMBLE 
int asmToCode(char *as, char res[255]);


/* validity checking */

// returns 0 for valid, does NOT set mstatus 
int valid(char *equation);

// extended regex pattern-match buf and run func on all of them, store result into res
// return non-zero on error, func should return -1 on error and lenght otherwise
int regplace(char *buf, char *pattern, int (*func)(char*), char *res);

int removeMatches(char* e);


/* String to string conversion, all of them return -1 for error, lenght otherwise */

int sxtoi(char *hex);
int sbtoi(char *bin);
int sotoi(char *oct);


#endif
