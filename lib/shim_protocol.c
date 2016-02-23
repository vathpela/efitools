#include <efi.h>
#include <efilib.h>

#include <guid.h>
#include <pecoff.h>
#include <sha256.h>
#include <efiauthenticated.h>
#include <pkcs7verify.h>
#include <variables.h>
#include <shim_protocol.h>
#include <console.h>

static EFI_PKCS7_VERIFY_PROTOCOL *p7vp;

/*
 * The Plcs7Verify protocol doesn't take raw signature lists and lengths,
 * it takes a null terminated list of pointers to signature lists, so
 * make the conversion
 */
static EFI_SIGNATURE_LIST **to_cert_list(VOID *data, UINTN len)
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

static EFI_STATUS shimprotocol_verify (void *buffer, UINT32 size)
{
	EFI_STATUS status;
	PE_COFF_LOADER_IMAGE_CONTEXT context;
	UINT8 hash[SHA256_DIGEST_SIZE];
	VOID *db = NULL, *dbx = NULL;
	EFI_SIGNATURE_LIST **dblist, **dbxlist;
	UINTN db_len, dbx_len;
	int i;

	if (!variable_is_secureboot() || variable_is_setupmode())
		return EFI_SUCCESS;

	status = pecoff_read_header(&context, buffer);
	if (status != EFI_SUCCESS)
		goto out;

	status = sha256_get_pecoff_digest_mem(buffer, size, hash);
	if (status != EFI_SUCCESS)
		goto out;

	get_variable(L"db", (UINT8 **)&db, &db_len, SIG_DB);
	get_variable(L"dbx", (UINT8 **)&dbx, &dbx_len, SIG_DB);

	dblist = to_cert_list(db, db_len);
	dbxlist = to_cert_list(dbx, dbx_len);

	for (i = 0; ; i++) {
		WIN_CERTIFICATE *cert;

		status = pecoff_get_signature(&context, buffer, &cert, i);
		if (status != EFI_SUCCESS)
			break;

		status = p7vp->VerifySignature(p7vp, (VOID *)(cert + 1),
					       cert->dwLength - sizeof(*cert),
					       hash, sizeof(hash),
					       dblist, dbxlist, NULL);

		if (status == EFI_SUCCESS)
			goto out;
	}
	status = EFI_ACCESS_DENIED;

 out:
	if (db)
		FreePool(db);
	if (dbx)
		FreePool(dbx);
	if (dblist)
		FreePool(dblist);
	if (dbxlist)
		FreePool(dbxlist);

	return status;
}

static SHIM_LOCK shim_protocol_interface = {
	.Verify = shimprotocol_verify,
};
static EFI_HANDLE shim_protocol_handle;

EFI_STATUS
shim_protocol_install(EFI_PKCS7_VERIFY_PROTOCOL *p)
{
	p7vp = p;
	return BS->InstallProtocolInterface(&shim_protocol_handle, &MOK_OWNER, EFI_NATIVE_INTERFACE, &shim_protocol_interface);
}

void
shim_protocol_uninstall(void)
{
	BS->UninstallProtocolInterface(shim_protocol_handle, &MOK_OWNER, &shim_protocol_interface);
}
