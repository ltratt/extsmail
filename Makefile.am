SUBDIRS = compat

bin_PROGRAMS = extsmail extsmaild

BUILT_SOURCES = conf_parser.tab.c externals_parser.tab.c

nodist_extsmail_SOURCES = conf_parser.tab.c conf_tokenizer.c
extsmail_SOURCES = extsmail.c common.c common.h conf.h

nodist_extsmaild_SOURCES = conf_parser.tab.c conf_tokenizer.c \
	externals_parser.tab.c externals_tokenizer.c
extsmaild_SOURCES =  extsmaild.c common.c common.h conf.h \
	externals.h compat/strtonum.h compat/strtonum.c

CLEANFILES = conf_parser.tab.[ch] conf_tokenizer.c \
	externals_parser.tab.[ch] externals_tokenizer.c

man1_MANS = extsmail.1 extsmaild.1
man5_MANS = extsmail.conf.5 extsmail.externals.5

EXTRA_DIST = conf_parser.y conf_tokenizer.l \
	externals_parser.y externals_tokenizer.l \
	$(man1_MANS) $(man5_MANS)


common.c: conf_parser.tab.c
conf_tokenizer.c: conf_parser.tab.c
externals_tokenizer.c: externals_parser.tab.c

conf_parser.tab.c: conf_parser.y
	@$(YACC) -p yyc -d -b conf_parser $(DESTDIR)$(srcdir)/conf_parser.y


conf_tokenizer.c: conf_tokenizer.l
	@$(LEX) -Pyyc -o conf_tokenizer.c $(DESTDIR)$(srcdir)/conf_tokenizer.l


externals_parser.tab.c: externals_parser.y
	@$(YACC) -p yye -d -b externals_parser $(DESTDIR)$(srcdir)/externals_parser.y


externals_tokenizer.c: externals_tokenizer.l
	@$(LEX) -Pyye -o externals_tokenizer.c $(DESTDIR)$(srcdir)/externals_tokenizer.l
