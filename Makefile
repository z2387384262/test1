# Kernel module
obj-m += kernel_module.o

# User-space program
USER_PROG = user_program
USER_SRCS = user_program.c

all: modules user_bin

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

user_bin: $(USER_SRCS)
	$(CC) $(CFLAGS) -o $(USER_PROG) $(USER_SRCS) $(LDFLAGS)

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f $(USER_PROG) *.o

# Phony targets
.PHONY: all modules user_bin clean
