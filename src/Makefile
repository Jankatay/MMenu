CC = gcc -Wall -g
LDGTK = `pkg-config --libs gtk4`
INGTK = `pkg-config --cflags gtk4`

run: main
	./main

main: main.c
	$(CC) $(INGTK) -o main main.c $(LDGTK)

.PHONY: clean
clean:
	rm main
