#include <efi.h>
#include <efilib.h>

#include <efiauthenticated.h>
#include <guid.h>
#include <pkcs7verify.h>
#include <variables.h>
#include <execute.h>
#include <pecoff.h>

#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

static CHAR16 *p7bin = L"\\Pkcs7VerifyDxe.efi";
static EFI_PKCS7_VERIFY_PROTOCOL *pkcs7verifyprotocol;

EFI_STATUS
pkcs7verify_get_protocol(EFI_HANDLE image, EFI_PKCS7_VERIFY_PROTOCOL **p7vp, CHAR16 **error)
{
	EFI_LOADED_IMAGE *li;
	EFI_DEVICE_PATH *loadpath = NULL;
	CHAR16 *PathName = NULL;
	EFI_HANDLE loader_handle;
	EFI_STATUS status;

	status = BS->LocateProtocol(&PKCS7_VERIFY_PROTOCOL_GUID,
				    NULL, (VOID **)p7vp);

	if (status == EFI_SUCCESS)
		return status;

	Print(L"Platform doesn't provide PKCS7_VERIFY protocol, trying to load\n");

	status = BS->HandleProtocol(image, &IMAGE_PROTOCOL, (VOID **)&li);
	if (status != EFI_SUCCESS) {
		*error = L"Can't find loaded image protocol";
		return status;
	}

	status = generate_path(p7bin, li, &loadpath, &PathName);
	if (status != EFI_SUCCESS) {
		*error = L"generate_path failed";
		return status;
	}

	status = BS->LoadImage(FALSE, image, loadpath, NULL, 0, &loader_handle);
	if (status != EFI_SUCCESS) {
		*error = L"LoadImage failed for external module";
		return status;
	}

	status = BS->StartImage(loader_handle, NULL, NULL);
	if (status != EFI_SUCCESS) {
		*error = L"StartImage failed for external module (loaded OK)";
		return status;
	}

	status = BS->LocateProtocol(&PKCS7_VERIFY_PROTOCOL_GUID,
				    NULL, (VOID **)p7vp);

	if (status != EFI_SUCCESS)
		*error = L"Loaded module but it didn't provide the pkcs7Verify protocol";
	else
		pkcs7verifyprotocol = *p7vp;

	return status;
}

/*
 * Checks the variable for the binary hash.  Returns 1 if found, 0 if
 * not and -1 on error.
 */
static int
pkcs7verify_is_hash_present(CHAR16 *var, EFI_GUID owner, VOID *data, UINTN len)
{
	EFI_GUID **hashes;
	UINT8 *hash;
	int count, i;
	int present  = -1;

	hashes = AllocatePool(allowed_hashes_size * sizeof(EFI_GUID *));
	if (!hashes)
		goto out;

	count = hashes_in_variable(var, owner, hashes);
	if (count < 0)
		goto out;

	for (i = 0; i < count; i++) {
		if (CompareGuid(hashes[i], &EFI_CERT_SHA256_GUID) == 0) {
			hash = AllocatePool(SHA256_DIGEST_SIZE);
			if (!hash)
				goto out;
			if (sha256_get_pecoff_digest_mem(data, len, hash) != EFI_SUCCESS) {
				FreePool(hash);
				goto out;
			}
			if (find_in_variable_esl(var, owner, hash, SHA256_DIGEST_SIZE) == EFI_SUCCESS) {
				present = 1;
				FreePool(hash);
				goto out;
			}
			FreePool(hash);
		} else {
			Print(L"FIXME: found an unrecognised hash algorithm %g\n",
			      hashes[i]);
			goto out;
		}
	}
	present = 0;
 out:
	if (hashes)
		FreePool(hashes);
	return present;
}


BOOLEAN
pkcs7verify_deny(VOID *data, UINTN len)
{
	int deny;

	deny = pkcs7verify_is_hash_present(L"dbx", SIG_DB, data, len);
	if (deny == 1 || deny < 0) {
		deny = 1;
		goto out;
	}
	deny = pkcs7verify_is_hash_present(L"MokListX", MOK_OWNER, data, len);
	if (deny == 1 || deny < 0)
		deny = 1;
 out:
	return deny ? TRUE : FALSE;
}

/*
 * The Plcs7Verify protocol doesn't take raw signature lists and lengths,
 * it takes a null terminated list of pointers to signature lists, so
 * make the conversion
 */
EFI_SIGNATURE_LIST **
pkcs7verify_to_cert_list(VOID *data, UINTN len)
{
	EFI_SIGNATURE_LIST  *CertList, **retval;
	
	int size, count=0;

	if (!data)
		return data;

	certlist_for_each_certentry(CertList, data, size, len)
		count++;

	retval = AllocatePool((count + 1) * sizeof(void *));
	if (!retval)
		return NULL;
	count = 0;
	certlist_for_each_certentry(CertList, data, size, len)
		retval[count++] = CertList;
	retval[count] = NULL;

	return retval;
}

BOOLEAN
pkcs7verify_allow(VOID *data, UINTN len)
{
	PE_COFF_LOADER_IMAGE_CONTEXT context;
	UINT8 hash[SHA256_DIGEST_SIZE];
	BOOLEAN allow = FALSE;
	CHAR16 *check[] = { L"MokList", L"db" };
	CHAR16 *forbid[] = { L"MokListX", L"dbx" };
	EFI_GUID owners[] = { MOK_OWNER, SIG_DB };
	EFI_STATUS status;
	int i;

	status = pecoff_read_header(&context, data);
	if (status != EFI_SUCCESS)
		goto out;

	/* FIXME: this is technically wrong, because the hash
	 * could be non-sha256, but it isn't a security breach
	 * because we'll refuse a binary we should have accepted */
	status = sha256_get_pecoff_digest_mem(data, len, hash);
	if (status != EFI_SUCCESS)
		goto out;

	/* first look up the hashes because the verify protocol can't
	 * do this anyway */

	if (find_in_variable_esl(L"MokList", MOK_OWNER, hash, SHA256_DIGEST_SIZE) == EFI_SUCCESS || 
	    find_in_variable_esl(L"db", SIG_DB, hash, SHA256_DIGEST_SIZE) == EFI_SUCCESS) {
		allow = TRUE;
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(check); i++) {
		VOID *db = NULL, *dbx = NULL;
		EFI_SIGNATURE_LIST **dblist = NULL, **dbxlist = NULL;
		UINTN db_len = 0, dbx_len = 0;
		int j;

		status = get_variable(check[i], (UINT8 **)&db, &db_len, owners[i]);
		if (status != EFI_SUCCESS)
			goto next;
		status = get_variable(forbid[i], (UINT8 **)&dbx, &dbx_len, owners[i]);
		if (status != EFI_SUCCESS && status != EFI_NOT_FOUND)
			goto next;
		dblist = pkcs7verify_to_cert_list(db, db_len);
		if (status != EFI_NOT_FOUND)
			dbxlist = pkcs7verify_to_cert_list(dbx, dbx_len);
		if ((db_len != 0 && dblist == NULL) ||
		    (dbx_len != 0 && dbxlist == NULL))
			goto next;
		for (j = 0; ; j++) {
			WIN_CERTIFICATE *cert;

			status = pecoff_get_signature(&context, data,
						      &cert, j);
			if (status != EFI_SUCCESS)
				break;

			status = pkcs7verifyprotocol->
				VerifySignature(pkcs7verifyprotocol,
						(VOID *)(cert + 1),
						cert->dwLength - sizeof(*cert),
						hash, sizeof(hash),
						dblist, dbxlist, NULL);

			if (status == EFI_SUCCESS) {
				allow = TRUE;
				break;
			}
		}
	next:
		if (dblist)
			FreePool(dblist);
		if (dbxlist)
			FreePool(dbxlist);
		if (db)
			FreePool(db);
		if (dbx)
			FreePool(dbx);
		if (allow)
			break;
	}

 out:
	return allow;


}
