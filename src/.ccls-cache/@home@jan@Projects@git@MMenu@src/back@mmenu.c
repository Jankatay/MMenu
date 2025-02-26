#include "mmenu.h"

enum MMenuStatus mstatus = ERR_OK;
void (*freem)(void*, size_t); 

// global disassembler
csh *handler = NULL;
cs_insn *instructions = NULL;

// global assembler
ks_engine *ks = NULL;

void initMMenu() {
	mpf_set_default_prec(216); // precision
	mp_get_memory_functions(NULL, NULL, &freem);
	handler = malloc( sizeof(handler) );

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

int codeToAsm(uint8_t *opcode, int len, char res[32][64]) {
	// disassemble opcode into instructions
	size_t count = cs_disasm(*handler, opcode, len, 0, 0, &instructions);

	// sanitize
	if(count <= 0) {
		cs_free(instructions, count);
		mstatus = ERR_DISASSEMBLE;
		return -1;
	}

	// load instructions into res.
	int i;
	[[maybe_unused]] char *mnemonic, *op_str;
	for(i = 0; i < count; i++) {
		mnemonic = instructions[i].mnemonic;
		op_str = instructions[i].op_str;
		strcpy(res[i], mnemonic);
		if(op_str[0]) {
			strcat(res[i], " ");
			strcat(res[i], op_str);
		}
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

intmax_t xtoi(char *hex) {
	char *endptr; 
	int res = strtoll(hex, &endptr, 16);
	if (endptr == hex) {
		mstatus = ERR_CONVERSION;
		return 0;
	}
	mstatus = ERR_OK;
	return res;
}

char* itox(intmax_t num) {
	char *hex = malloc(64);
	int len = snprintf(hex, 64, "0x%lx", num);
	if (len < 0) {
		mstatus = ERR_CONVERSION;
		return 0;
	}
	mstatus = ERR_OK;
	return hex;
}

intmax_t btoi(char *bin) {
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

char* itob(intmax_t num) {
	char *bin = malloc(255);
	int len = snprintf(bin, 255, "0b%lb", num);
	if (len < 0) {
		mstatus = ERR_CONVERSION;
		return 0;
	}
	mstatus = ERR_OK;
	return bin;
}

intmax_t otoi(char *oct) {
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

char* itoo(intmax_t num) {
	char *oct = malloc(64);
	int len = snprintf(oct, 64, "0o%lo", num);
	if (len < 0) {
		mstatus = ERR_CONVERSION;
		return 0;
	}
	mstatus = ERR_OK;
	return oct;
}

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
	mpf_t val;
	char *start = hex;
	// offset in case of negatives etc.
	switch(hex[0]) {
		case('-'): hex[2] = hex[0]; //nobreak
		case('0'): hex+=2; break;
		case('+'): hex += 3; break;
		default: return -1; break;
	}
	// convert
	int initError = mpf_init_set_str(val, hex, 16);
	if(initError) { mpf_clear(val); return -1; }
	int len = gmp_sprintf(start, "%Ff", val);
	mpf_clear(val);
	if(len < 0) { return -1; }
	return strlen(hex);
}

int sbtoi(char *bin) {
	mpf_t val;
	char *start = bin;
	// offset in case of negatives etc.
	switch(bin[0]) {
		case('-'): bin[2] = bin[0]; //nobreak
		case('0'): bin+=2; break;
		case('+'): bin += 3; break;
		default: return -1; break;
	}
	// convert
	int initError = mpf_init_set_str(val, bin, 2);
	if(initError) { mpf_clear(val); return -1; }
	int len = gmp_sprintf(start, "%Ff", val);
	mpf_clear(val);
	if(len < 0) { return -1; }
	return strlen(bin);
}

int sotoi(char *oct) {
	mpf_t val;
	char *start = oct;
	// offset in case of negatives etc.
	switch(oct[0]) {
		case('-'): oct[2] = oct[0]; //nobreak
		case('0'): oct+=2; break;
		case('+'): oct += 3; break;
		default: return -1; break;
	}
	// convert
	int initError = mpf_init_set_str(val, oct, 2);
	if(initError) { mpf_clear(val); return -1; }
	int len = gmp_sprintf(start, "%Ff", val);
	mpf_clear(val);
	if(len < 0) { return -1; }
	return strlen(oct);
}

bool getFinalOutput(char *equ, mpf_t res) {
	// convert all assembly
	char out[255] = "", copy[255] = "";
	strcpy(copy, equ);
	int statusErr;
	statusErr = regplace(copy, "\"[^\"]*\"", replaceAsmWithCode, out);
	if(statusErr) {
		mstatus = ERR_CONVERSION;
		return false;
	}
	
	// check validity
	int valError = valid(out);
	if(valError) {
		mstatus = ERR_SYNTAX;
		return false;
	}

	// solve 
	char *sol = solve(out);
	if(!sol) {
		mstatus = ERR_OTHER;
		return false;
	}

	// return result
	mpf_set_str(res, sol, 10);
	free(sol);
	return true;
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

int charCodeToAsm(char *ubuf, char cbuf[32][64]) {
	if(!ubuf[0]) {
		cbuf[0][0] = '\0';
		return 0;
	}
	uint8_t bytes[255] = {};
	char temp[2];
	int len = 0;
	for(int i = 2; i < strlen(ubuf)-1; i+=2) {
		strncpy(temp, ubuf+i, 2);
		bytes[len++] = xtoi(temp);
	}

	return codeToAsm(bytes, len, cbuf);
}

bool xtom(char *hex, mpf_t dst) {
	int convError = mpf_set_str(dst, hex, 16);
	if (convError) {
		mstatus = ERR_CONVERSION;
		return false;
	}
	mstatus = ERR_OK;
	return true;
}

bool btom(char *bin, mpf_t dst) {
	int convError = mpf_set_str(dst, bin, 2);
	if (convError) {
		mstatus = ERR_CONVERSION;
		return false;
	}
	mstatus = ERR_OK;
	return true;
}

bool otom(char *oct, mpf_t dst) {
	int convError = mpf_set_str(dst, oct, 8);
	if (convError) {
		mstatus = ERR_CONVERSION;
		return false;
	}
	mstatus = ERR_OK;
	return true;
}

bool mtox(mpf_t frac, char *dst) {
	// sanitize
	if(!dst) { return -1; }

	// calculate
	mp_exp_t expptr;
	char *buf = mpf_get_str(NULL, &expptr, 16, 50, frac);

	// return
	int res = strlen(buf)+1;
	strcpy(dst, buf);
	freem(buf, res);
	return res >= 0;
}

bool mtob(mpf_t frac, char *dst) {
	// sanitize
	if(!dst) { return -1; }

	// calculate
	mp_exp_t expptr;
	char *buf = mpf_get_str(NULL, &expptr, 2, 50, frac);

	// return
	int res = strlen(buf)+1;
	strcpy(dst, buf);
	freem(buf, res);
	return res >= 0;
}

bool mtoo(mpf_t frac, char *dst) {
	// sanitize
	if(!dst) { return -1; }

	// calculate
	mp_exp_t expptr;
	char *buf = mpf_get_str(NULL, &expptr, 8, 50, frac);
	
	// return
	int res = strlen(buf)+1;
	strcpy(dst, buf);
	freem(buf, res);
	return res >= 0;
}
