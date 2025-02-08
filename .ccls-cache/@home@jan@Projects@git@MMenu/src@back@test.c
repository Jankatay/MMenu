/* error status */
enum ErrorStatus {
	success,
	errSyntax,
	errOther
};
extern enum ErrorStatus errStatus;
extern enum ErrorStatus getLexerStatus();
extern int getOutput(const char*);
