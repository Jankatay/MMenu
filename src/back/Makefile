CC = gcc -g
LDFLAGS = -l:libcapstone.a -l:libkeystone.a -l:libstdc++.a -lqalculate -l:libstdc++.a -l:libm.a -lgmp

run: main
	./main

lib: main.c mmenu.c wrapper.cpp
	$(CC) -c -o main.o main.c 

main: main.c mmenu.c wrapper.cpp
	$(CC) -o main main.c mmenu.c wrapper.cpp $(LDFLAGS)


.PHONY : clean
clean:
	rm main 
