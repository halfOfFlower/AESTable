all:
	gcc -g aes.c rand.c main.c -o aescoder
clean:
	rm -rf *.o aescoder
