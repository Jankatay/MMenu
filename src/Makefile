CC = gcc -Wall -g
LDGTK = `pkg-config --libs gtk4`
INGTK = `pkg-config --cflags gtk4`
LDCAP = `pkg-config --libs capstone`
LDKEY = `pkg-config --libs keystone`
LDQAL = -lqalculate -lgmp
LDFLAGS = -lstdc++ -lm

run: main
	./main

main: main.c ./back/mmenu.c ./back/wrapper.cpp 
	$(CC) $(INGTK) -o main main.c shortcut-handler.c ./back/mmenu.c ./back/wrapper.cpp $(LDGTK) $(LDCAP) $(LDKEY) $(LDQAL) $(LDFLAGS)

.PHONY: clean
clean:
	rm main
