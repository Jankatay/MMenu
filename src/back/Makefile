CC = gcc -g
LPATH = -L.
LDFLAGS = -l:libcapstone.a -l:libkeystone.a -l:libstdc++.a -lqalculate -l:libstdc++.a -l:libm.a 

run: main
	./main

main: main.c mmenu.c wrapper.cpp
	$(CC) $(LPATH) -o main main.c mmenu.c wrapper.cpp $(LDFLAGS)

.PHONY : clean
clean:
	rm main 
