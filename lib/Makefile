FILES = simple_file.o pecoff.o guid.o sha256.o console.o \
	execute.o configtable.o shell.o security_policy.o \
	shim_protocol.o pkcs7verify.o

LIBFILES = $(FILES) kernel_efivars.o openssl_sign.o
EFILIBFILES = $(patsubst %.o,%.efi.o,$(FILES)) variables.o 

include ../Make.rules

lib.a: $(LIBFILES)
lib-efi.a: $(EFILIBFILES)

clean:
	rm -f lib.a
	rm -f lib-efi.a
	rm -f $(LIBFILES)
	rm -f $(EFILIBFILES)

