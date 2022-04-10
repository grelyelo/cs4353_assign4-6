all: main util
	gcc -o assign4-6 main.o util.o -lm -lpcap -ldnet

util:
	gcc -Wall -c src/util.c

main:
	gcc -Wall -c src/main.c 

