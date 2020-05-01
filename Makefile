CFLAGS = -g
OFLAGS = -g -c
CC = gcc
PACKAGE_NAME = "tree"

install:
	@$(CC) $(OFLAGS) *.c
	@$(CC) $(CFLAGS) *.o -o $(PACKAGE_NAME)
	@rm -f *.o
	@echo "Install complete"

clean:
	@rm -f *.o
	@rm -f $(PACKAGE_NAME)
	@echo "Clean complete"