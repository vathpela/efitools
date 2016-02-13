/*
 * Copyright 2012 <James.Bottomley@HansenPartnership.com>
 *
 * see COPYING file
 *
 * Install and remove a platform security2 override policy
 */

#include <efi.h>
#include <efilib.h>

#include <guid.h>
#include <sha256.h>
#include <variables.h>
#include <simple_file.h>
#include <errors.h>

#include <security_policy.h>

/*
 * See the UEFI Platform Initialization manual (Vol2: DXE) for this
 */
struct _EFI_SECURITY2_PROTOCOL;
struct _EFI_SECURITY_PROTOCOL;
typedef struct _EFI_SECURITY2_PROTOCOL EFI_SECURITY2_PROTOCOL;
typedef struct _EFI_SECURITY_PROTOCOL EFI_SECURITY_PROTOCOL;
typedef EFI_DEVICE_PATH EFI_DEVICE_PATH_PROTOCOL;

typedef EFI_STATUS (EFIAPI *EFI_SECURITY_FILE_AUTHENTICATION_STATE) (
			const EFI_SECURITY_PROTOCOL *This,
			UINT32 AuthenticationStatus,
			const EFI_DEVICE_PATH_PROTOCOL *File
								     );
typedef EFI_STATUS (EFIAPI *EFI_SECURITY2_FILE_AUTHENTICATION) (
			const EFI_SECURITY2_PROTOCOL *This,
			const EFI_DEVICE_PATH_PROTOCOL *DevicePath,
			VOID *FileBuffer,
			UINTN FileSize,
			BOOLEAN	BootPolicy
								     );

struct _EFI_SECURITY2_PROTOCOL {
	EFI_SECURITY2_FILE_AUTHENTICATION FileAuthentication;
};

struct _EFI_SECURITY_PROTOCOL {
	EFI_SECURITY_FILE_AUTHENTICATION_STATE  FileAuthenticationState;
};


static UINT8 *security_policy_esl = NULL;
static UINTN security_policy_esl_len;

static EFI_STATUS
security_policy_check_mok(void *data, UINTN len)
{
	EFI_STATUS status;
	UINT8 hash[SHA256_DIGEST_SIZE];
	UINT32 attr;
	UINT8 *VarData;
	UINTN VarLen;

	/* first check is MokSBState.  If we're in insecure mode, boot
	 * anyway regardless of dbx contents */
	status = get_variable_attr(L"MokSBState", &VarData, &VarLen,
				   MOK_OWNER, &attr);
	if (status == EFI_SUCCESS) {
		UINT8 MokSBState = VarData[0];

		FreePool(VarData);
		if ((attr & EFI_VARIABLE_RUNTIME_ACCESS) == 0
		    && MokSBState)
			return EFI_SUCCESS;
	}

	status = sha256_get_pecoff_digest_mem(data, len, hash);
	if (status != EFI_SUCCESS)
		return status;

	if (find_in_variable_esl(L"dbx", SIG_DB, hash, SHA256_DIGEST_SIZE)
	    == EFI_SUCCESS)
		/* MOK list cannot override dbx */
		return EFI_SECURITY_VIOLATION;

	status = get_variable_attr(L"MokList", &VarData, &VarLen, MOK_OWNER,
				   &attr);
	if (status != EFI_SUCCESS)
		goto check_tmplist;

	FreePool(VarData);

	if (attr & EFI_VARIABLE_RUNTIME_ACCESS)
		goto check_tmplist;

	if (find_in_variable_esl(L"MokList", MOK_OWNER, hash, SHA256_DIGEST_SIZE) == EFI_SUCCESS)
		return EFI_SUCCESS;

 check_tmplist:
	if (security_policy_esl
	    && find_in_esl(security_policy_esl, security_policy_esl_len, hash,
			   SHA256_DIGEST_SIZE) == EFI_SUCCESS)
		return EFI_SUCCESS;

	return EFI_SECURITY_VIOLATION;
}

static EFIAPI EFI_SECURITY_FILE_AUTHENTICATION_STATE esfas = NULL;
static EFIAPI EFI_SECURITY2_FILE_AUTHENTICATION es2fa = NULL;

EFI_STATUS
EFIAPI
security2_policy_authentication (
	const EFI_SECURITY2_PROTOCOL *This,
	const EFI_DEVICE_PATH_PROTOCOL *DevicePath,
	VOID *FileBuffer,
	UINTN FileSize,
	BOOLEAN	BootPolicy
				 )
{
	EFI_STATUS status, auth;

	/* Chain original security policy */

	status = es2fa(This, DevicePath, FileBuffer, FileSize, BootPolicy);

	/* if OK, don't bother with MOK check */
	if (status == EFI_SUCCESS)
		return status;

	auth = security_policy_check_mok(FileBuffer, FileSize);

	if (auth == EFI_SECURITY_VIOLATION || auth == EFI_ACCESS_DENIED)
		/* return previous status, which is the correct one
		 * for the platform: may be either EFI_ACCESS_DENIED
		 * or EFI_SECURITY_VIOLATION */
		return status;

	return auth;
}

EFI_STATUS
EFIAPI
security_policy_authentication (
	const EFI_SECURITY_PROTOCOL *This,
	UINT32 AuthenticationStatus,
	const EFI_DEVICE_PATH_PROTOCOL *DevicePathConst
	)
{
	EFI_STATUS status, fail_status;
	EFI_DEVICE_PATH *DevPath 
		= DuplicateDevicePath((EFI_DEVICE_PATH *)DevicePathConst),
		*OrigDevPath = DevPath;
	EFI_HANDLE h;
	EFI_FILE *f;
	VOID *FileBuffer;
	UINTN FileSize;
	CHAR16* DevPathStr;

	/* Chain original security policy */
	status = esfas(This, AuthenticationStatus, DevicePathConst);

	/* if OK avoid checking MOK: It's a bit expensive to
	 * read the whole file in again (esfas already did this) */
	if (status == EFI_SUCCESS)
		goto out;

	/* capture failure status: may be either EFI_ACCESS_DENIED or
	 * EFI_SECURITY_VIOLATION */
	fail_status = status;

	status = BS->LocateDevicePath(&SIMPLE_FS_PROTOCOL, &DevPath, &h);
	if (status != EFI_SUCCESS)
		goto out;

	DevPathStr = DevicePathToStr(DevPath);

	status = simple_file_open_by_handle(h, DevPathStr, &f,
					    EFI_FILE_MODE_READ);
	FreePool(DevPathStr);
	if (status != EFI_SUCCESS)
		goto out;

	status = simple_file_read_all(f, &FileSize, &FileBuffer);
	simple_file_close(f);
	if (status != EFI_SUCCESS)
		goto out;

	status = security_policy_check_mok(FileBuffer, FileSize);
	FreePool(FileBuffer);

	if (status == EFI_ACCESS_DENIED || status == EFI_SECURITY_VIOLATION)
		/* return what the platform originally said */
		status = fail_status;
 out:
	FreePool(OrigDevPath);
	return status;
}

EFI_STATUS
security_policy_install(void)
{
	EFI_SECURITY_PROTOCOL *security_protocol;
	EFI_SECURITY2_PROTOCOL *security2_protocol = NULL;
	EFI_STATUS status;

	if (esfas)
		/* Already Installed */
		return EFI_ALREADY_STARTED;

	/* Don't bother with status here.  The call is allowed
	 * to fail, since SECURITY2 was introduced in PI 1.2.1
	 * If it fails, use security2_protocol == NULL as indicator */
	BS->LocateProtocol(&SECURITY2_PROTOCOL_GUID, NULL,
			   (VOID **)&security2_protocol);

	status = BS->LocateProtocol(&SECURITY_PROTOCOL_GUID, NULL,
				    (VOID **)&security_protocol);
	if (status != EFI_SUCCESS)
		/* This one is mandatory, so there's a serious problem */
		return status;

	if (security2_protocol) {
		es2fa = security2_protocol->FileAuthentication;
		security2_protocol->FileAuthentication = 
			security2_policy_authentication;
		/* check for security policy in write protected memory */
		if (security2_protocol->FileAuthentication
		    !=  security2_policy_authentication)
			return EFI_ACCESS_DENIED;
	}

	esfas = security_protocol->FileAuthenticationState;
	security_protocol->FileAuthenticationState =
		security_policy_authentication;
	/* check for security policy in write protected memory */
	if (security_protocol->FileAuthenticationState
	    !=  security_policy_authentication)
		return EFI_ACCESS_DENIED;

	return EFI_SUCCESS;
}

EFI_STATUS
security_policy_uninstall(void)
{
	EFI_STATUS status;

	if (esfas) {
		EFI_SECURITY_PROTOCOL *security_protocol;

		status = BS->LocateProtocol(&SECURITY_PROTOCOL_GUID, NULL,
					    (VOID **)&security_protocol);

		if (status != EFI_SUCCESS)
			return status;

		security_protocol->FileAuthenticationState = esfas;
		esfas = NULL;
	} else {
		/* nothing installed */
		return EFI_NOT_STARTED;
	}

	if (es2fa) {
		EFI_SECURITY2_PROTOCOL *security2_protocol;

		status = BS->LocateProtocol(&SECURITY2_PROTOCOL_GUID, NULL,
					    (VOID **)&security2_protocol);

		if (status != EFI_SUCCESS)
			return status;

		security2_protocol->FileAuthentication = es2fa;
		es2fa = NULL;
	}

	return EFI_SUCCESS;
}

void
security_protocol_set_hashes(unsigned char *esl, int len)
{
	security_policy_esl = esl;
	security_policy_esl_len = len;
}
