SYSCALL_INTERCEPT_DIR:=$(abspath $(CURDIR)/syscall_intercept/install)

INCLUDE = -I$(SYSCALL_INTERCEPT_DIR)/include
CFLAGS = -O2 -W -Wall -Wextra -fPIC
LDFLAGS = -L$(SYSCALL_INTERCEPT_DIR)/lib -Wl,-rpath=$(SYSCALL_INTERCEPT_DIR)/lib -lsyscall_intercept -ldl -lpthread

.PHONY: debug release tests

release: shim tests

debug: CFLAGS += -g -DDEBUG
debug: shim tests

shim: shim.o userlib.o mem.o nvme.o pa_maps.o
	gcc $(CFLAGS) $(INCLUDE) $^ $(LDFLAGS) -shared -o libshim.so

tests:
	make -C tests/

%.o: %.c 
	gcc $(CFLAGS) $(INCLUDE) -c $<

clean:
	$(RM) *.o
	$(RM) *.so
	$(RM) userlib.log
	make -C tests/ clean
