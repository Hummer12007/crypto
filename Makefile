SRCDIR := src
BUILDDIR := build
BINDIR := bin

CPPFLAGS := -Iinclude

all: bin/aes bin/aes_test #bin/sha

bin/aes: CFLAGS := -march=native
bin/aes: build/aes.o build/aes_main.o build/common.o build/ts.o

bin/aes_test: CFLAGS := -march=native
bin/aes_test: build/aes.o build/aes_test.o build/hexify.o

bin/sha: LDLIBS := -lcrypto
bin/sha: build/sha3.o build/ts.o build/common.o build/sha_main.o

$(BINDIR)/%: |$(BINDIR)
	$(CC) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS) -o $@

$(BUILDDIR)/%.o: $(SRCDIR)/%.c |$(BUILDDIR)
	$(COMPILE.c) $^ -o $@

$(BINDIR):
	mkdir $@

$(BUILDDIR):
	mkdir $@

clean:
	$(RM) -r bin build
