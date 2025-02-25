#include "mmenu.h"

enum MMenuStatus mstatus = ERR_OK;

// global disassembler
csh *handler = NULL;
cs_insn *instructions = NULL;

// global assembler
ks_engine *ks = NULL;

void initMMenu() {
	handler = malloc( sizeof(handler) );
	instructions = malloc( sizeof(cs_insn) );

	// capstone status
	cs_err cstatus = cs_open(CS_ARCH_X86, CS_MODE_64, handler);
	if(cstatus != CS_ERR_OK) {
		mstatus = ERR_INIT;
		return;
	}
	// keystone status
	ks_err kstatus = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
	if(kstatus != KS_ERR_OK) {
		mstatus = ERR_INIT;
	}

	// done initializing
	mstatus = ERR_OK;
}

void freeMMenu() {
	if(handler) { cs_close(handler); handler=NULL; }
	if(ks) 			{ ks_close(ks); ks=NULL;}
}

int codeToAsm(uint8_t *opcode, char res[32][64]) {
	// disassemble opcode into instructions
	size_t count = cs_disasm(*handler, opcode, sizeof(opcode)-1, 0, 0, &instructions);

	// sanitize
	if(count <= 0) {
		cs_free(instructions, count);
		mstatus = ERR_DISASSEMBLE;
		return -1;
	}

	// load instructions into res.
	int i;
	for(i = 0; i < count; i++) {
		int len = snprintf(res[i], 64, "%s\t%s;", instructions[i].mnemonic, instructions[i].op_str);
		res[i+1][0] = '\0';
		if(len < 0) {
			cs_free(instructions, count);
			mstatus = ERR_DISASSEMBLE;
			return -1;
		}
	}

	// exit
	cs_free(instructions, count);
	mstatus = ERR_OK;
	return i;
}

int asmToCode(char *as, char res[255]) {
	// init keystone
	unsigned char *encode;
	size_t count;
	size_t size;

	// assemble 'as' and sanitize
	int kerror = ks_asm(ks, as, 0, &encode, &size, &count);
	if(kerror) {
		mstatus = ERR_ASSEMBLE;
		return -1;
	}

	// Load the opcodes into temp 
	strcpy(res, "0x");
	char temp[255] = "";
	for(int i = 0; i < count; i++) {
		int len = snprintf(temp, 3, "%02x", encode[i]);
		if(len < 0 ) {
			mstatus = ERR_ASSEMBLE;
			res[0] = '\0';
			ks_free(encode);
			return -1;
		}
		strcat(res, temp);
	}

	// exit
	mstatus = ERR_OK;
	ks_free(encode);
	return size;
}

int xtoi(char *hex) {
	char *endptr; 
	int res = strtoll(hex, &endptr, 16);
	if (endptr == hex) {
		mstatus = ERR_CONVERSION;
		return 0;
	}
	mstatus = ERR_OK;
	return res;
}

char* itox(int num) {
	char *hex = malloc(64);
	int len = snprintf(hex, 64, "0x%x", num);
	if (len < 0) {
		mstatus = ERR_CONVERSION;
		return 0;
	}
	mstatus = ERR_OK;
	return hex;
}

int btoi(char *bin) {
	char *endptr; 
	int offset = 2;
	if(bin[0] == '-') { offset = 3; }
	int res = strtoll(bin+offset, &endptr, 2);
	if(endptr == bin) {
		mstatus = ERR_CONVERSION;
		return 0;
	}
	if(bin[0] == '-') { res *= -1; }
	mstatus = ERR_OK;
	return res;
}

char* itob(int num) {
	char *bin = malloc(255);
	int len = snprintf(bin, 255, "0b%b", num);
	if (len < 0) {
		mstatus = ERR_CONVERSION;
		return 0;
	}
	mstatus = ERR_OK;
	return bin;
}

int otoi(char *oct) {
	char *endptr;
	int offset = 2;
	if(oct[0] == '-') { offset = 3; }
	int res = strtoll(oct+offset, &endptr, 8);
	if(endptr == oct) {
		mstatus = ERR_CONVERSION;
		return 0;
	}
	mstatus = ERR_OK;
	if(oct[0] == '-'){ res *= -1; }
	return res;
}

char* itoo(int num) {
	char *oct = malloc(64);
	int len = snprintf(oct, 64, "0o%o", num);
	if (len < 0) {
		mstatus = ERR_CONVERSION;
		return 0;
	}
	mstatus = ERR_OK;
	return oct;
}

/*
int calculateNumbers(char *equ) {
	char *out = solve(equ);
	char **nptr = {};
	int res = 0;

	// Algebra in the number factory? how quaint. I must inquire about this with my collegueas.
	if(strncmp(out, "x =", 3) == 0) {
		char* copy = out+4;
		res = strtoll(copy, nptr, 10);
	} else {
		res = strtoll(out, nptr, 10);
	}

	// sanitize
	if(**nptr) {
		mstatus = ERR_SYNTAX;
		free(out);
		return -1;
	}

	// return
	mstatus = ERR_OK;
	free(out);
	return 0;
}
*/
int regplace(char *buf, char *pattern, int (*func)(char*), char *res) {
	// init 
	int matchIndex, bufIndex = 0;
	int regError, emptyPattern = 1;
	int lenOut, lenMatch;
	regmatch_t pmatch;
	char out[255];
	regex_t preg;

	// compute regex
	regError = regcomp(&preg, pattern, 0);
	if(regError) {
		return 1;
	}

	// for each match 
	while( !(regError = regexec(&preg, buf+bufIndex, preg.re_nsub+1, &pmatch, REG_EXTENDED)) ) {
		emptyPattern = 0;
		// run func
		lenMatch = pmatch.rm_eo - pmatch.rm_so;
		matchIndex = pmatch.rm_so;
		strncpy(out, buf+bufIndex+matchIndex, lenMatch);
		out[lenMatch] = '\0';
		lenOut = func(out);
		// store result
		strncat(res, buf+bufIndex, matchIndex);
		strncat(res, out, lenOut);
		// increment index
		bufIndex += pmatch.rm_eo;
	} 

	// append rest of the buf
	strcat(res, buf+bufIndex);
	
	// ensure it was nomatch.
	if(regError != REG_NOMATCH) {
		return 1;
	}

	// there was no match at all to begin with.
	if(emptyPattern) {
		strcpy(res, buf);
	}

	// init
	return 0;
}

int removeMatches(char* e) {
	if(!e){ return 1; }
	strcpy(e, "");
	return 0;
}

// regex.
static char *validList[] = {
	"0x[0-9a-fA-F]\\+", 	  // hex
	"0b[01]\\+", 					  // binary
	"0o[0-7]\\+", 				  // octal 
	"[-+*/^|()=]\\+", 			// operators
	"[0-9]\\+.[0-9]\\+", 	  // float 
	"[0-9]\\+", 					  // decimal
	"[ \t\n]\\+", 					// whitespace
	"x\\+", 								// algebra
};
static size_t lenValidList = sizeof(validList)/sizeof(validList[0]);

int valid(char *equation) {
	// init
	if(!equation) { return 1; }
	char copy[255] = "", res[255] = "";
	int regErr;

	// copy equation over to copy
	strcpy(copy, equation);

	// go through each item on the list and eliminate, then check if anything is left.
	for(int i = 0; i < lenValidList; i++) {
		// res = copy - pattern
		regErr = regplace(copy, validList[i], removeMatches, res);
		if(regErr) { return 1; }
		// copy = res
		strcpy(copy, res);
		res[0] = '\0';
	}

	// return 0 if nothing left, 1 otherwise
	return copy[0] != '\0';
}

int sxtoi(char *hex) {
	int num = xtoi(hex);
	int status = sprintf(hex, "%d", num);
	if(mstatus) { return -1; }
	mstatus = ERR_OK;
	return status;
}

int sbtoi(char *bin) {
	int num = btoi(bin);
	int status = sprintf(bin, "%d", num);
	if(status < 0) {
		return 1;
	}
	mstatus = ERR_OK;
	return status;
}

int sotoi(char *oct) {
	int num = otoi(oct);
	int status = sprintf(oct, "%d", num);
	if(mstatus) { return -1; }
	mstatus = ERR_OK;
	return status;
}

float getFinalOutput(char *equ) {
	// convert all assembly
	char out[255] = "", copy[255] = "";
	strcpy(copy, equ);
	int statusErr;
	statusErr = regplace(copy, "\"[^\"]*\"", replaceAsmWithCode, out);
	if(statusErr) {
		mstatus = ERR_CONVERSION;
		return 0;
	}
	
	// check validity
	int valError = valid(out);
	if(valError) {
		mstatus = ERR_SYNTAX;
		return 0;
	}

	// solve 
	char *sol = solve(out);
	if(!sol) {
		mstatus = ERR_OTHER;
		return 0;
	}
	// return result
	float res = atof(sol);
	free(sol);
	return res;
}

int replaceAsmWithCode(char* as) {
	char out[255] = "";
	as[strlen(as)-1] = '\0';
	asmToCode(as+1, out);
	strcpy(as, out);
	return strlen(out);
}

int charToUInt8(char *cbuf, uint8_t *ubuf) {
	int i;
	for(i = 0; i < strlen(cbuf); i++) {
		sscanf(cbuf+2+i*2, "%2hhx", &ubuf[i]);
	}
	return i;
}
