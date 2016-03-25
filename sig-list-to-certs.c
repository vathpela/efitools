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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/err.h>

#include <variables.h>
#include <guid.h>

int
main(int argc, char *argv[])
{
	char *certfile, *efifile, *name, *esl_name;
	const char *progname = argv[0];
	int output_esl = 0;

	if (argc != 3 && argc != 4) {
		printf("Usage: %s <efi sig list file> <cert file base name>\n", progname);
		exit(1);
	}

	if (strcmp("-e", argv[1]) == 0) {
		output_esl = 1;
		argc--;
		argv++;
	}

	efifile = argv[1];
	certfile = argv[2];
	name = malloc(strlen(certfile)+10);
	esl_name = malloc(strlen(certfile)+10);

	int fd = open(efifile, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open file %s: ", efifile);
		perror("");
		exit(1);
	}

	struct stat st;
	if (fstat(fd, &st) < 0) {
		fprintf(stderr, "Failed to stat file %s: ", efifile);
		perror("");
		exit(1);
	}

	void *buf = malloc(st.st_size);
	if (!buf) {
		fprintf(stderr, "Malloc failed: ");
		perror("");
		exit(1);
	}

	if (read(fd, buf, st.st_size) != st.st_size) {
		fprintf(stderr, "Failed to read %d bytes from %s: ",
			(int)st.st_size, efifile);
		perror("");
		exit(1);
	}
	close(fd);

	EFI_SIGNATURE_LIST *sl;
	int s, count = 0;
	certlist_for_each_certentry(sl, buf, s, st.st_size) {
		EFI_SIGNATURE_DATA *sd;
		const char *ext;

		certentry_for_each_cert(sd, sl) {

			FILE *g;

			if (memcmp(&sl->SignatureType, &EFI_CERT_X509_GUID, sizeof(EFI_GUID)) == 0) {
				printf("X509 ");
				ext = "der";
			} else if (memcmp(&sl->SignatureType, &EFI_CERT_TYPE_PKCS7_GUID, sizeof(EFI_GUID)) == 0) {
				printf("PKCS7 ");
				ext = "pk7";
			} else if (memcmp(&sl->SignatureType, &EFI_CERT_RSA2048_GUID, sizeof(EFI_GUID)) == 0) {
				printf("RSA2048 ");
				ext = "rsa";
			} else if (memcmp(&sl->SignatureType, &EFI_CERT_SHA256_GUID, sizeof(EFI_GUID)) == 0) {
				printf("SHA256 ");
				ext = "hash";
			} else {
				printf("UNKNOWN ");
				ext = "txt";
			}
			printf("Header sls=%d, header=%d, sig=%d\n",
			       sl->SignatureListSize, sl->SignatureHeaderSize, sl->SignatureSize - (UINT32)OFFSET_OF(EFI_SIGNATURE_DATA, SignatureData));

			EFI_GUID *guid = &sd->SignatureOwner;

			sprintf(esl_name, "%s-%d.esl",certfile,count);
			sprintf(name, "%s-%d.%s",certfile,count++,ext);
			printf("file %s: Guid %s\n", name, guid_to_str(guid));

			if (output_esl) {
				g = fopen(esl_name, "w");
				fwrite(sl, 1, sl->SignatureListSize, g);
				fclose(g);
			}

			g = fopen(name, "w");
			fwrite(sd->SignatureData, 1, sl->SignatureSize - OFFSET_OF(EFI_SIGNATURE_DATA, SignatureData), g);
			printf("Written %d bytes\n", sl->SignatureSize - (UINT32)OFFSET_OF(EFI_SIGNATURE_DATA, SignatureData));
			fclose(g);
		}
	}

	return 0;
}
