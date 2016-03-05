/*
 * Copyright 2016 <James.Bottomley@HansenPartnership.com>
 *
 * see COPYING file
 *
 * Replacement for shim.efi which is signed by your own key
 * and installs the shim protocol verifier for grub to use
 * so the secure boot chain is unbroken
 */

#include <efi.h>
#include <efilib.h>

#include <console.h>
#include <guid.h>
#include <efiauthenticated.h>
#include <execute.h>
#include <shim_protocol.h>
#include <pkcs7verify.h>

static const CHAR16 *loader = L"\\grub.efi";
static const CHAR16 *fallback = L"\\fallback.efi";

EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS efi_status;
	EFI_PKCS7_VERIFY_PROTOCOL *p7vp;
	CHAR16 *error;
	void *ptr;

	InitializeLib(image, systab);

	efi_status = pkcs7verify_get_protocol(image, &p7vp, &error);

	if (efi_status != EFI_SUCCESS) {
		console_error(error, efi_status);
		return efi_status;
	}

	efi_status = shim_protocol_install();
	if (efi_status != EFI_SUCCESS)
		console_error(L"Failed to install shim protocol", efi_status);


	efi_status = BS->LocateProtocol(&MOK_OWNER,
				    NULL, &ptr);
	if (efi_status != EFI_SUCCESS)
		console_error(L"Failed to locate shim protocol", efi_status);

	efi_status = execute(image, loader);
	if (efi_status == EFI_SUCCESS)
		return efi_status;

	console_error(L"Failed to start primary loader", efi_status);

	efi_status = execute(image, fallback);

	if (efi_status != EFI_SUCCESS)
		console_error(L"Failed to start fallback loader", efi_status);

	return efi_status;
}
