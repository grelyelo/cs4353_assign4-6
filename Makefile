all: main util
	gcc -o assign4-6 main.o util.o -lm -lpcap -ldnet -ldumbnet

util:
	gcc -Wall -c src/util.c

main:
	gcc -Wall -c src/main.c 

clean:
	rm assign4-6
