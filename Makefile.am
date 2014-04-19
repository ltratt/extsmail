bin_PROGRAMS = extsmail extsmaild

extsmail_SOURCES = common.h common.c conf.h extsmail.c
nodist_extsmail_SOURCES = conf_parser.tab.h conf_parser.tab.c conf_tokenizer.c

extsmaild_SOURCES = common.h common.c conf.h externals.h extsmaild.c \
compat/strtonum.h compat/strtonum.c
nodist_extsmaild_SOURCES = conf_parser.tab.h conf_parser.tab.c conf_tokenizer.c \
externals_parser.tab.h externals_parser.tab.c externals_tokenizer.c

BUILT_SOURCES = conf_parser.tab.c conf_tokenizer.c externals_parser.tab.c externals_tokenizer.c

man1_MANS = extsmail.1 extsmaild.1
man5_MANS = extsmail.conf.5 extsmail.externals.5

EXTRA_DIST = conf_parser.y externals_parser.y conf_tokenizer.l externals_tokenizer.l \
extsmail.1 extsmaild.1 extsmail.conf.5  extsmail.externals.5

CLEANFILES = conf_tokenizer.c externals_tokenizer.c conf_parser.tab.h externals_parser.tab.h


conf_parser.tab.c: conf_parser.y
	$(YACC) -p yyc -d -b conf_parser $(DESTDIR)$(srcdir)/conf_parser.y


conf_tokenizer.c: conf_tokenizer.l
	$(LEX) -Pyyc -oconf_tokenizer.c $(DESTDIR)$(srcdir)/conf_tokenizer.l


externals_parser.tab.c: externals_parser.y
	$(YACC) -p yye -d -b externals_parser $(DESTDIR)$(srcdir)/externals_parser.y


externals_tokenizer.c: externals_tokenizer.l
	$(LEX) -Pyye -oexternals_tokenizer.c $(DESTDIR)$(srcdir)/externals_tokenizer.l
