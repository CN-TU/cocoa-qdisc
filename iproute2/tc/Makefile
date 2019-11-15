# SPDX-License-Identifier: GPL-2.0

include ../config.mk

SHARED_LIBS ?= y

TCMODULES :=
TCMODULES += q_cocoa.o

TCSO :=
TCSO += q_cocoa.so

TCOBJ :=
TCOBJ += $(TCMODULES)
LDLIBS += -L. -lm

ifeq ($(SHARED_LIBS),y)
LDLIBS += -ldl
LDFLAGS += -Wl,-export-dynamic
endif

CFLAGS += -DCONFIG_GACT -DCONFIG_GACT_PROB

YACC := bison
LEX := flex
CFLAGS += -DYY_NO_INPUT

MODDESTDIR := $(DESTDIR)$(LIBDIR)/tc

%.so: %.c
	$(QUIET_CC)$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -shared -fpic $< -o $@

all: $(TCSO)

install: all
	mkdir -p $(MODDESTDIR)
	for i in $(TCSO); \
	do install -m 755 $$i $(MODDESTDIR); \
	done

clean:
	rm -f $(TCOBJ) *.so emp_ematch.yacc.h; \
	rm -f emp_ematch.yacc.*

%.yacc.c: %.y
	$(QUIET_YACC)$(YACC) $(YACCFLAGS) -o $@ $<

%.lex.c: %.l
	$(QUIET_LEX)$(LEX) $(LEXFLAGS) -o$@ $<

# our lexer includes the header from yacc, so make sure
# we don't attempt to compile it before the header has
# been generated as part of the yacc step.
emp_ematch.lex.o: emp_ematch.yacc.c

ifneq ($(SHARED_LIBS),y)

tc: static-syms.o
static-syms.o: static-syms.h
static-syms.h: $(wildcard *.c)
	files="$^" ; \
	for s in `grep -B 3 '\<dlsym' $$files | sed -n '/snprintf/{s:.*"\([^"]*\)".*:\1:;s:%s::;p}'` ; do \
		sed -n '/'$$s'[^ ]* =/{s:.* \([^ ]*'$$s'[^ ]*\) .*:extern char \1[] __attribute__((weak)); if (!strcmp(sym, "\1")) return \1;:;p}' $$files ; \
	done > $@

endif
