#ifndef MMENU_H
#define MMENU_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
// dependencies
#include <capstone/capstone.h> 			
#include <keystone/keystone.h>
#include <gmp.h>


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

// Get final output in a single function. Check return or mstatus for ERR_OK
// ERR_SYNTAX ERR_CONVERSION ERR_OTHER.
bool getFinalOutput(char *equ, mpf_t res);


/* Converting data functions */
// Convert between hex and int
// ERR_CONVERSION ERR_OTHER 
intmax_t xtoi(char *hex);
char* itox(intmax_t num); // Free result when done

// between binary and int
// ERR_CONVERSION ERR_OTHER 
intmax_t btoi(char *bin);
char* itob(intmax_t num); // Free result when done

// between octagonal and int
// ERR_CONVERSION ERR_OTHER 
intmax_t otoi(char *oct);
char* itoo(intmax_t num); // Free result when done.


/* Assember and disassembler */

// disassemble x86_64 opcodes into res line by line. return how many lines or -1 on error
// ERR_DISASSEMBLE
int codeToAsm(uint8_t *opcode, int len, char res[32][64]);

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
int replaceAsmWithCode(char* as);


/* other */

// codeToAsm for char*. Result is in cbuf and returns line amount or -1 for error
int charCodeToAsm(char *ubuf, char cbuf[32][64]);


/* bignum */
// uses fraction instead of double for more precision, eventually should replace others.
// return false on error, result stored in dst.
bool xtom(char *hex, mpf_t dst); 								// xtoi
bool btom(char *bin, mpf_t dst); 								// btoi
bool otom(char *oct, mpf_t dst); 								// otoi
bool mtox(mpf_t frac, char* dst); 								// itox
bool mtob(mpf_t frac, char* dst); 								// itob
bool mtoo(mpf_t frac, char* dst); 								// itoo
extern void (*freem)(void*, size_t); 				// use to free chars 

#endif
