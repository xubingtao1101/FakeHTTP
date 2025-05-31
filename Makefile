CROSS_PREFIX :=
CC=$(CROSS_PREFIX)gcc
STRIP=$(CROSS_PREFIX)strip

override CFLAGS+=-O3 -std=c99 -pedantic -Wall -Wextra
override LDFLAGS+=-lnetfilter_queue -lnfnetlink -lmnl

PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
BUILDDIR=build

FAKEHTTP=$(BUILDDIR)/fakehttp
FAKEHTTP_NFQ=$(BUILDDIR)/fakehttp_nfq

ifeq ($(STATIC), 1)
	override CFLAGS += -static
endif

all: $(FAKEHTTP) $(FAKEHTTP_NFQ)

clean:
	$(RM) -r $(BUILDDIR)

$(FAKEHTTP): src/fakehttp.sh
	mkdir -p $(BUILDDIR)
	install -m 755 $< $@

$(FAKEHTTP_NFQ): src/fakehttp_nfq.c
	mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	$(STRIP) $@

install: all
	mkdir -p $(DESTDIR)$(BINDIR)
	install -m 755 fakehttp_nfq $(DESTDIR)$(BINDIR)/fakehttp_nfq
	install -m 755 fakehttp $(DESTDIR)$(BINDIR)/fakehttp

uninstall:
	$(RM) $(DESTDIR)$(BINDIR)/fakehttp_nfq
	$(RM) $(DESTDIR)$(BINDIR)/fakehttp

.PHONY: all clean install uninstall
