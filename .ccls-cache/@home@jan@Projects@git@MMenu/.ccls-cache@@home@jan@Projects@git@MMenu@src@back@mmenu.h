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
enum MMenuStatus mstatus = ERR_OK;

/* library ends for programmers to use */

// Initialize status and global pointers for this library
// ERR_INIT
void initMMenu();

// Free all pointers made by initMMenu.
void freeMMenu();

// Get final output in a single function.
// ERR_SYNTAX ERR_CONVERSION ERR_OTHER.
int getFinalOutput(const char *equ);


/* Converting data functions */

// Calculate numbers and solve for 'x' if given.
// ERR_SYNTAX ERR_OTHER
int calculateNumbers(const char *equ);

// Convert between hex and int
// ERR_CONVERSION ERR_OTHER 
int xtoi(const char *hex);
char* itox(const int num);

// between binary and int
// ERR_CONVERSION ERR_OTHER 
int btoi(const char *bin);
char* itob(const int num);

// between octagonal and int
// ERR_CONVERSION ERR_OTHER 
int otoi(const char *oct);
char* itoo(const int num);


/* Assember and disassembler */

// disassemble hex x86_64 opcodes into res line by line. res fills with opcodes as it returns how many lines. 
// ERR_SYNTAX ERR_DISASSEMBLE ERR_OTHER
int codeToAsm(const uint8_t *opcode, char res[32][64]);

// assemble x86_64 assembly code into res as a string of opcodes. returns how many lines.
int asmToCode(const char *as, char res[255]);


/* Empty */

#endif
