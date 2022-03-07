CC     = gcc

# Compilation flags
LIBDIR = /usr/local/lib/mfdf
INCLUDEDIR   = ./include
CFLAGS = -Wall -Wextra -L$(LIBDIR) -I$(INCLUDEDIR)

# Directories
BINDIR = ./bin
OBJDIR = ./obj
SRCDIR = ./src

# Libraries
BASELIB    = -lmfdfuser
EXTRALIB = -pthread

# Other stuff
DEPS = ./include/common.h
DEMO = mfdf-demo
TEST = mfdf-test-cases


# Compile each source file
$(OBJDIR)/%.o: $(SRCDIR)/%.c $(DEPS) make-directories
	$(CC) -c -o $@ $< $(CFLAGS)

# make -> generate both demo and test-cases
all: demo test-cases

# make demo -> generate demo
demo: $(OBJDIR)/demo.o $(OBJDIR)/common.o
	$(CC) -o $(BINDIR)/$(DEMO) $^ $(CFLAGS) $(BASELIB)

# make test-cases -> generate test-cases
test-cases: $(OBJDIR)/test-cases.o $(OBJDIR)/common.o
	$(CC) -o $(BINDIR)/$(TEST) $^ $(CFLAGS) $(BASELIB) $(EXTRALIB)

# Cleanup rules
.PHONY: clean make-directories

clean:
	$(RM) -r $(OBJDIR) $(BINDIR)

make-directories:
	mkdir -p $(BINDIR) $(OBJDIR)
