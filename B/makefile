target: virusDetector

virusDetector: virusDetector.o
	gcc -m32 -g -Wall -o virusDetector virusDetector.o

virusDetector.o: AntiVirus.c
	gcc -m32 -g -Wall -c -o virusDetector.o AntiVirus.c

PHONY: clean

clean:
	rm -f virusDetector.o virusDetector 