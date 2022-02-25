IDIR = ./include
CC = gcc
CFLAGS = -I$(IDIR) -Wall -Wextra
OBJDIR = ./obj
BINDIR = ./bin
SRCDIR = ./src
DEPS   = ./include/user.h
OBJS   = ./obj/user.o ./obj/test.o
BIN    = mfdf-test-cases

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(DEPS) make-directories
	$(CC) -c -o $@ $< $(CFLAGS)

test-cases: $(OBJS)
	$(CC) -o $(BINDIR)/$(BIN) $^ $(CFLAGS)

.PHONY: clean make-directories

make-directories:
	mkdir -p $(OBJDIR) $(BINDIR)

clean:
	$(RM) -r $(OBJDIR)/ $(BINDIR)/
