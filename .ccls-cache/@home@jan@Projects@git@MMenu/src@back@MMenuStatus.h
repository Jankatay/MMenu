#ifndef MMENUSTATUS_H
#define MMENUSTATUS_H

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

#endif
