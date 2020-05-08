OFLAGS = -g
CFLAGS = -g -c -Wall
CLIBS = -lcrypto -lssl
CC = gcc
PACKAGE_NAME = "PinguAV"

install:
	@$(CC) $(CFLAGS) $(CLIBS) *.c
	@$(CC) $(OFLAGS) *.o $(CLIBS) -o $(PACKAGE_NAME)
	@rm -f *.o
	@echo "Install complete"

clean:
	@rm -f *.o
	@rm -f $(PACKAGE_NAME)
	rm -i sigs
	@echo "Clean complete"