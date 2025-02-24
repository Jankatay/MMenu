#include "mmenu.h"
enum MMenuStatus mstatus = ERR_OK;

// global disassembler
csh *handler = NULL;
cs_insn *instructions = NULL;

// global assembler
ks_engine *ks = NULL;

void initMMenu() {
	handler = malloc( sizeof(handler) );
	cs_insn *instructions = malloc( sizeof(cs_insn) );

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
}

void freeMMenu() {
	if(handler) { cs_close(handler); handler=NULL; }
	if(ks) 			{ ks_close(ks); ks=NULL;}
}

int codeToAsm(const uint8_t *opcode, char res[32][64]) {
	// disassemble opcode into instructions
	size_t count = cs_disasm(*handler, opcode, sizeof(opcode)-1, 0, 0, &instructions);

	// sanitize
	if(count <= 0) {
		cs_free(instructions, count);
		mstatus = ERR_DISASSEMBLE;
		return 0;
	}

	// load instructions into res.
	int i;
	for(i = 0; i < count; i++) {
		int len = snprintf(res[i], 64, "%s\t%s;", instructions[i].mnemonic, instructions[i].op_str);
		if(len >= sizeof res[i]) {
			cs_free(instructions, count);
			mstatus = ERR_DISASSEMBLE;
			return 0;
		}
	}

	// exit
	cs_free(instructions, count);
	return i;
}

int asmToCode(const char *as, char res[255]) {
	// init keystone
	unsigned char *encode;
	size_t count;
	size_t size;

	// assemble 'as' and sanitize
	int kerror = ks_asm(ks, as, 0, &encode, &size, &count);
	if(kerror) {
		mstatus = ERR_ASSEMBLE;
		return 0;
	}

	// Load the opcodes into temp 
	strcpy(res, "0x");
	char temp[255] = "";
	for(int i = 0; i < count; i++) {
		int len = snprintf(temp, 3, "%02x", encode[i]);
		if(len != 2) {
			mstatus = ERR_ASSEMBLE;
			res[0] = '\0';
			ks_free(encode);
			return 0;
		}
		strcat(res, temp);
	}

	// res = 0x, res += temp.
	ks_free(encode);
	return size;
}

