/*
 * Copyright 2019 <James.Bottomley@HansenPartnership.com>
 *
 * see COPYING file
 */

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/engine.h>

#include <openssl_sign.h>

int
sign_efi_var_ssl(char *payload, int payload_size, EVP_PKEY *pkey, X509 *cert,
		 unsigned char **sig, int *sigsize)
{
	BIO *bio_data = BIO_new_mem_buf(payload, payload_size);
	PKCS7 *p7;

	p7 = PKCS7_sign(NULL, NULL, NULL, bio_data, PKCS7_BINARY|PKCS7_PARTIAL|PKCS7_DETACHED|PKCS7_NOATTR);
	const EVP_MD *md = EVP_get_digestbyname("SHA256");
	PKCS7_sign_add_signer(p7, cert, pkey, md, PKCS7_BINARY|PKCS7_DETACHED|PKCS7_NOATTR);
	PKCS7_final(p7, bio_data, PKCS7_BINARY|PKCS7_DETACHED|PKCS7_NOATTR);

	*sig = NULL;
	*sigsize = i2d_PKCS7_SIGNED(p7->d.sign, sig);
	PKCS7_free(p7);
	ERR_print_errors_fp(stdout);

	return 0;
}

int
sign_efi_var(char *payload, int payload_size, char *keyfile, char *certfile,
	     unsigned char **sig, int *sigsize, char *engine)
{
	int ret;

	ERR_load_crypto_strings();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_ciphers();
	/* here we may get highly unlikely failures or we'll get a
	 * complaint about FIPS signatures (usually becuase the FIPS
	 * module isn't present).  In either case ignore the errors
	 * (malloc will cause other failures out lower down */
	ERR_clear_error();

	BIO *cert_bio = BIO_new_file(certfile, "r");
	if (!cert_bio) {
		ERR_print_errors_fp(stdout);
		fprintf(stderr, "error reading certificate %s\n", certfile);
		return 1;
	}
	X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
	BIO_free(cert_bio);
	if (!cert) {
		ERR_print_errors_fp(stdout);
		fprintf(stderr, "error reading certificate %s\n", certfile);
		return 1;
	}

	EVP_PKEY *pkey = read_private_key(engine, keyfile);
	if (!pkey) {
		ERR_print_errors_fp(stdout);
		fprintf(stderr, "error reading private key %s\n", keyfile);
		return 1;
	}
	ret = sign_efi_var_ssl(payload, payload_size, pkey, cert,
			       sig, sigsize);
	EVP_PKEY_free(pkey);
	X509_free(cert);

	return ret;
}

static EVP_PKEY *
read_pem_private_key(char *keyfile)
{
	BIO *key = BIO_new_file(keyfile, "r");
	EVP_PKEY *pkey;

	if (!key) {
		ERR_print_errors_fp(stdout);
		fprintf(stderr, "error reading private key file %s\n", keyfile);
		return NULL;
	}
	pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);
	BIO_free(key);

	if (!pkey) {
		ERR_print_errors_fp(stdout);
		fprintf(stderr, "error processing private key file %s\n", keyfile);
		return NULL;
	}
	return pkey;
}

static int ui_read(UI *ui, UI_STRING *uis)
{
	char password[128];

	if (UI_get_string_type(uis) != UIT_PROMPT)
		return 0;

	EVP_read_pw_string(password, sizeof(password), "Enter engine key pass phrase:", 0);
	UI_set_result(ui, uis, password);
	return 1;
}

static EVP_PKEY *
read_engine_private_key(char *engine, char *keyfile)
{
	UI_METHOD *ui;
	ENGINE *e;
	EVP_PKEY *pkey = NULL;

	ENGINE_load_builtin_engines();
	e = ENGINE_by_id(engine);

	if (!e) {
		fprintf(stderr, "Failed to load engine: %s\n", engine);
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	ui = UI_create_method("sbsigntools");
	if (!ui) {
		fprintf(stderr, "Failed to create UI method\n");
		ERR_print_errors_fp(stderr);
		goto out_free;
	}
	UI_method_set_reader(ui, ui_read);

	if (!ENGINE_init(e)) {
		fprintf(stderr, "Failed to initialize engine %s\n", engine);
		ERR_print_errors_fp(stderr);
		goto out_free;
	}

	pkey = ENGINE_load_private_key(e, keyfile, ui, NULL);
	ENGINE_finish(e);

 out_free:
	ENGINE_free(e);
	return pkey;
}

EVP_PKEY *
read_private_key(char *engine, char *keyfile)
{
	if (engine)
		return read_engine_private_key(engine, keyfile);
	else
		return read_pem_private_key(keyfile);
}
