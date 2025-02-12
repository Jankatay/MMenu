CC=gcc -std=c99 -D_POSIX_SOURCE -g 
YC=bison -d 
LC=flex -l

all: lib
	@(echo; echo "Done making the static library parser.a")
	@(echo "Usage : use int getOutput(const char*) to interact with the library")
	@(echo "attach --static -lfl at the end of your compiler flags")
	make main

main: main.c lib
	$(CC) -o main main.c parser.a --static -lfl


lib: parser.c lexer.c
	$(CC) -o parser.o -c parser.c 
	$(CC) -o lexer.o -c lexer.c 
	ar rcs parser.a ./parser.o ./lexer.o

parser.c:
	$(YC) -o ./parser.c ./parser/parser.y

lexer.c:
	$(LC) -o ./lexer.c ./parser/lexer.l

.PHONY: clean
clean:
	rm parser.h;
	rm parser.c;
	rm lexer.c;
	rm *.o;
	rm main;
	rm parser.a;
