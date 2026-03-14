# Firewallo - Firewall Manager for Debian GNU/Linux
# Build system

CC       = gcc
CFLAGS   = -std=c17 -Wall -Wextra -Wpedantic -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
LDFLAGS  =
PREFIX   = /usr/local
ETCDIR   = /etc/firewallo
WEBDIR   = $(PREFIX)/share/firewallo/web

SRCDIR   = src
INCDIR   = include
BUILDDIR = build
TESTDIR  = tests

# Source files
LIB_SRCS  = $(wildcard $(SRCDIR)/lib/*.c)
CLI_SRCS  = $(wildcard $(SRCDIR)/cli/*.c)
WEB_SRCS  = $(wildcard $(SRCDIR)/web/*.c)
TEST_SRCS = $(wildcard $(TESTDIR)/test_*.c)

# Object files
LIB_OBJS  = $(LIB_SRCS:$(SRCDIR)/%.c=$(BUILDDIR)/%.o)
CLI_OBJS  = $(CLI_SRCS:$(SRCDIR)/%.c=$(BUILDDIR)/%.o)
WEB_OBJS  = $(WEB_SRCS:$(SRCDIR)/%.c=$(BUILDDIR)/%.o)

# Output
LIB      = $(BUILDDIR)/libfirewallo.a
CLI_BIN  = $(BUILDDIR)/firewallo
WEB_BIN  = $(BUILDDIR)/firewallo-web

.PHONY: all clean install uninstall test debug lib cli web

all: $(CLI_BIN) $(WEB_BIN)

lib: $(LIB)

cli: $(CLI_BIN)

web: $(WEB_BIN)

debug: CFLAGS += -g -O0 -DDEBUG -fsanitize=address
debug: LDFLAGS += -fsanitize=address
debug: all

# Static library
$(LIB): $(LIB_OBJS)
	@mkdir -p $(dir $@)
	ar rcs $@ $^

# CLI binary
$(CLI_BIN): $(CLI_OBJS) $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $(CLI_OBJS) $(LIB)

# Web binary
$(WEB_BIN): $(WEB_OBJS) $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $(WEB_OBJS) $(LIB)

# Compile source to object
$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

# Tests
test: $(LIB)
	@mkdir -p $(BUILDDIR)/tests
	@failed=0; total=0; \
	for t in $(TEST_SRCS); do \
		name=$$(basename $$t .c); \
		total=$$((total + 1)); \
		$(CC) $(CFLAGS) -I$(INCDIR) -o $(BUILDDIR)/tests/$$name $$t $(LIB) && \
		echo "Running $$name..." && \
		$(BUILDDIR)/tests/$$name || { echo "FAIL: $$name"; failed=$$((failed + 1)); }; \
	done; \
	echo ""; \
	echo "Results: $$((total - failed))/$$total passed"; \
	test $$failed -eq 0

# Install
install: all
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -d $(DESTDIR)$(ETCDIR)
	install -d $(DESTDIR)$(WEBDIR)
	install -d $(DESTDIR)/lib/systemd/system
	install -m 755 $(CLI_BIN) $(DESTDIR)$(PREFIX)/sbin/firewallo
	install -m 755 $(WEB_BIN) $(DESTDIR)$(PREFIX)/sbin/firewallo-web
	@test -f $(DESTDIR)$(ETCDIR)/firewallo.json || \
		install -m 644 etc/firewallo/firewallo.json $(DESTDIR)$(ETCDIR)/firewallo.json
	cp -r web/* $(DESTDIR)$(WEBDIR)/
	install -m 644 systemd/firewallo.service $(DESTDIR)/lib/systemd/system/
	install -m 644 systemd/firewallo-web.service $(DESTDIR)/lib/systemd/system/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/sbin/firewallo
	rm -f $(DESTDIR)$(PREFIX)/sbin/firewallo-web
	rm -rf $(DESTDIR)$(WEBDIR)
	rm -f $(DESTDIR)/lib/systemd/system/firewallo.service
	rm -f $(DESTDIR)/lib/systemd/system/firewallo-web.service

clean:
	rm -rf $(BUILDDIR)
