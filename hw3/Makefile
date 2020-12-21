all:
	gcc -O0 -g -c pcapParser.c -o pcapParser.o
	gcc -O0 -g -c parser.c -o parser.o
	gcc pcapParser.o parser.o -o parse -lpcap
clean:
	rm pcapParser.o parser.o parse
