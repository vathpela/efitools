/*
 * Copyright 2012 <James.Bottomley@HansenPartnership.com>
 *
 * see COPYING file
 */
#include <stdint.h>
#define __STDC_VERSION__ 199901L
#include <efi.h>
#ifdef CONFIG_arm
/* FIXME:
 * arm efi leaves a visibilit pragma pushed that won't work for
 * non efi programs, so eliminate it */
#pragma GCC visibility pop
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>
#include <errno.h>
#include <ctype.h>

#include <PeImage.h>		/* for ALIGN_VALUE */
#include <sha256.h>
#include <efiauthenticated.h>
#include <guid.h>
#include <version.h>

#define ESC "\x1b"
#define BOLD(c) ESC "[0;" #c "m"
#define SHA256_TEXT_SIZE (SHA256_DIGEST_SIZE * 2)

static void
usage(const char *progname)
{
	printf("Usage: %s efi-binary [efi-binary ...] efi-signature-list\n", progname);
}

static void
help(const char *progname)
{
	usage(progname);
	printf("Produce an EFI Signature List file containing the sha256 hash of the\n"
	       "passed in EFI binary\n"
	       "\nOptions:\n"
	       "none\n"
	       );
}

static void
print_hash_error(char *text, int len, int pos)
{
	int i, added = 0;
	fflush(stdout);
	fprintf(stderr, "Invalid hash: ");
	for(i = 0; i < pos - 1; i++) {
		if (isspace(text[i])) {
			fprintf(stderr, "\\x%02x", text[i]);
			added += 3;
		} else {
			fprintf(stderr, "%c", text[i]);
		}
	}
	fprintf(stderr, "%s", BOLD(1));
	for(; i < len; i++) {
		if (isspace(text[i]))
			fprintf(stderr, "\\x%02x", text[i]);
		else
			fprintf(stderr, "%c", text[i]);
	}
	fprintf(stderr, "%s\n              ", BOLD(0));
	for(i = 0; i < pos + added - 1; i++)
		fprintf(stderr, " ");
	fprintf(stderr, "^ here\n");
	exit(1);
}

static int
read_hash_text(uint8_t *binary, char *text, int len)
{
	int i, j;
	char errbuf[SHA256_TEXT_SIZE + 9];
	memset(errbuf, 0, sizeof(errbuf));
	char extra = 0;

	if (len > SHA256_TEXT_SIZE) {
		if (!isspace(text[SHA256_TEXT_SIZE]))
			print_hash_error(text, MIN(len, SHA256_TEXT_SIZE + 8), SHA256_TEXT_SIZE + 1);
		extra = text[SHA256_TEXT_SIZE];
		text[SHA256_TEXT_SIZE] = 0;
	}

	for(i = 0, j = 0; i < SHA256_TEXT_SIZE; i+=2, j++) {
		char buf[3] = "XX";
		unsigned long val;
		if (!isxdigit(text[i])) {
			if (extra)
				text[SHA256_TEXT_SIZE] = extra;
			print_hash_error(text, MIN(len, SHA256_TEXT_SIZE + 8), i+1);
		}
		if (!isxdigit(text[i+1])) {
			if (extra)
				text[SHA256_TEXT_SIZE] = extra;
			print_hash_error(text, MIN(len, SHA256_TEXT_SIZE + 8), i+2);
		}

		memcpy(buf, text+i, 2);
		val = strtoul(buf, NULL, 16);

		binary[j] = val & 0xff;
	}
	if (extra)
		text[SHA256_TEXT_SIZE] = extra;
	return i;
}

int
main(int argc, char *argv[])
{
	char *efifile;
	const char *progname = argv[0];
	int i;
	int strings = 0;
	char *output;

	while (argc > 1) {
		if (strcmp("--version", argv[1]) == 0) {
			version(progname);
			exit(0);
		} else if (strcmp("--help", argv[1]) == 0) {
			help(progname);
			exit(0);
		} else if (strcmp("--strings", argv[1]) == 0) {
			strings = 1;
			argc--;
			argv++;
		} else  {
			break;
		}
	}

	if (argc < 3) {
		usage(progname);
		exit(1);
	}

	output = argv[argc-1];
	argc--;

	int hashes = argc - 1;
	UINT8 *hash = calloc(hashes, SHA256_DIGEST_SIZE);
	if (!hash) {
alloc_error:
		fprintf(stderr, "Couldn't allocate hashes: %m\n");
		exit(1);
	}

	for (i = 0; i < argc - 1; i++) {
		int j;
		struct stat st;

		int fdefifile = open(argv[i + 1], O_RDONLY);
		if (fdefifile == -1) {
			fprintf(stderr, "failed to open file %s: ", argv[1]);
			perror("");
			exit(1);
		}
		fstat(fdefifile, &st);
		efifile = malloc(ALIGN_VALUE(st.st_size + 1, 4096));
		memset(efifile, 0, ALIGN_VALUE(st.st_size + 1, 4096));
		read(fdefifile, efifile, st.st_size);
		close(fdefifile);
		if (strings) {
			int k = 0;
			j = strlen(efifile);

			if (j != st.st_size) {
				fprintf(stderr, "String hash file %s is malformed\n", argv[i + 1]);
				exit(1);
			}

			while (k < j) {
				if (j - k < SHA256_TEXT_SIZE)
					print_hash_error(efifile + k, j - k, j - k + 1);

				k += read_hash_text(hash + i * SHA256_DIGEST_SIZE, efifile + k, j - k);

				printf("HASH IS ");
				for (int l = 0; l < SHA256_DIGEST_SIZE; l++) {
					printf("%02x", hash[i * SHA256_DIGEST_SIZE + l]);
				}
				printf("\n");
				while (k < j && isspace(efifile[k]))
					k++;
				if (k < j) {
					UINT8 *new;
					hashes++;
					i++;
					new = realloc(hash, hashes * SHA256_DIGEST_SIZE);
					if (!new)
						goto alloc_error;
					hash = new;
					memset(hash + i * SHA256_DIGEST_SIZE, 0, SHA256_DIGEST_SIZE);
				}
			}
		} else {
			EFI_STATUS status;
			status = sha256_get_pecoff_digest_mem(efifile, st.st_size,
							      hash + i * SHA256_DIGEST_SIZE);
			if (status != EFI_SUCCESS) {
				printf("Failed to get hash of %s: %d\n", argv[i+1],
				       status);
				continue;
			}

			printf("HASH IS ");
			for (j = 0; j < SHA256_DIGEST_SIZE; j++) {
				printf("%02x", hash[i * SHA256_DIGEST_SIZE + j]);
			}
			printf("\n");
		}
	}
	UINT8 sig[sizeof(EFI_SIGNATURE_LIST) + (sizeof(EFI_SIGNATURE_DATA) - 1 + SHA256_DIGEST_SIZE) * hashes];

	EFI_SIGNATURE_LIST *l = (void *)sig;

	memset(sig, 0, sizeof(sig));
	l->SignatureType = EFI_CERT_SHA256_GUID;
	l->SignatureListSize = sizeof(sig);
	l->SignatureSize = 16 +32; /* UEFI defined */
	for (i = 0; i < hashes; i++) {
		EFI_SIGNATURE_DATA *d = (void *)sig + sizeof(EFI_SIGNATURE_LIST) + l->SignatureSize * i;
		d->SignatureOwner = MOK_OWNER;
		memcpy(&d->SignatureData, hash + i * SHA256_DIGEST_SIZE, SHA256_DIGEST_SIZE);
	}

	int fdoutfile = open(output, O_CREAT|O_WRONLY|O_TRUNC, S_IWUSR|S_IRUSR);
	if (fdoutfile == -1) {
		fprintf(stderr, "failed to open %s: ", output);
		perror("");
		exit(1);
	}
	write(fdoutfile, sig, sizeof(sig));
	close(fdoutfile);
	return 0;
}
