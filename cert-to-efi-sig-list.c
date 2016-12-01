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

#include <openssl/pem.h>
#include <openssl/err.h>

#include <guid.h>
#include <variables.h>
#include <version.h>

static void
usage(const char *progname)
{
	printf("Usage: %s [-g <guid>] <crt file> <efi sig list file>\n", progname);
}

static void
help(const char * progname)
{
	usage(progname);
	printf("Take an input X509 certificate (in PEM format) and convert it to an EFI\n"
	       "signature list file containing only that single certificate\n\n"
	       "Options:\n"
	       "\t-g <guid>        Use <guid> as the owner of the signature. If this is not\n"
	       "\t                 supplied, an all zero guid will be used\n"

	       );
	
}

int
main(int argc, char *argv[])
{
	char *efifile;
	const char *progname = argv[0];
	EFI_GUID owner = { 0 };
	int i;
	EFI_SIGNATURE_LIST *PkCerts;
	int PkCertLen = 0;
	struct {
		X509 *cert;
		int len;
	} certs[1024] = { {NULL, 0}, };
	int offset = 0;

	while (argc > 1) {
		if (strcmp("--version", argv[1]) == 0) {
			version(progname);
			exit(0);
		} else if (strcmp("--help", argv[1]) == 0) {
			help(progname);
			exit(0);
		} else if (strcmp("-g", argv[1]) == 0) {
			str_to_guid(argv[2], &owner);
			argv += 2;
			argc -= 2;
		} else {
			break;
		}
	}

	if (argc < 3) {
		exit(1);
	}
	if (argc > 1023) {
		exit(1);
	}

	efifile = argv[argc-1];
	argc--;

        ERR_load_crypto_strings();
        OpenSSL_add_all_digests();
        OpenSSL_add_all_ciphers();
	/* here we may get highly unlikely failures or we'll get a
	 * complaint about FIPS signatures (usually becuase the FIPS
	 * module isn't present).  In either case ignore the errors
	 * (malloc will cause other failures out lower down */
	ERR_clear_error();

	for (i = 1; i < argc; i++) {
		char *certfile = argv[i];
	        BIO *cert_bio = BIO_new_file(certfile, "r");
	        X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
		int certlen = i2d_X509(cert, NULL);

		certlen += sizeof(EFI_SIGNATURE_LIST) + OFFSET_OF(EFI_SIGNATURE_DATA, SignatureData);
		PkCertLen += certlen;

		certs[i-1].cert = cert;
		certs[i-1].len = certlen;
	}

	PkCerts = malloc (PkCertLen);
	if (!PkCerts) {
		fprintf(stderr, "failed to malloc cert\n");
		exit(1);
	}

	for (i = 0; i < argc-1; i++) {
		EFI_SIGNATURE_LIST *PkCert;

		PkCert = (EFI_SIGNATURE_LIST *)((intptr_t)PkCerts + offset);

		unsigned char *tmp = (unsigned char *)PkCert + sizeof(EFI_SIGNATURE_LIST) + OFFSET_OF(EFI_SIGNATURE_DATA, SignatureData);
		i2d_X509(certs[i].cert, &tmp);
		PkCert->SignatureListSize   = certs[i].len;
		PkCert->SignatureSize       = (UINT32) (certs[i].len - sizeof(EFI_SIGNATURE_LIST));
		PkCert->SignatureHeaderSize = 0;
		PkCert->SignatureType = EFI_CERT_X509_GUID;

		EFI_SIGNATURE_DATA *PkCertData = (void *)PkCert + sizeof(EFI_SIGNATURE_LIST);

		PkCertData->SignatureOwner = owner;

		offset += certs[i].len;
	}

	FILE *f = fopen(efifile, "w");
	if (!f) {
		fprintf(stderr, "failed to open efi file %s: ", efifile);
		perror("");
		exit(1);
	}
	if (fwrite(PkCerts, 1, PkCertLen, f) != PkCertLen) {
		perror("Did not write enough bytes to efi file");
		exit(1);
	}


	return 0;
}
