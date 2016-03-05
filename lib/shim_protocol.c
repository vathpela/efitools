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

static EFI_STATUS shimprotocol_context(void *data, unsigned int size,
				       PE_COFF_LOADER_IMAGE_CONTEXT *context)
{
	return pecoff_read_header(context, data);
}

static EFI_STATUS shimprotocol_verify(void *buffer, UINT32 size)
{
	EFI_STATUS status;

	if (!variable_is_secureboot() || variable_is_setupmode())
		return EFI_SUCCESS;

	if (pkcs7verify_deny(buffer, size))
		return EFI_ACCESS_DENIED;

	if (pkcs7verify_allow(buffer, size))
		return EFI_SUCCESS;

	return EFI_ACCESS_DENIED;


	return status;
}

static SHIM_LOCK shim_protocol_interface = {
	.Verify = shimprotocol_verify,
	.Context = shimprotocol_context,
};
static EFI_HANDLE shim_protocol_handle;

EFI_STATUS
shim_protocol_install(void)
{
	return BS->InstallProtocolInterface(&shim_protocol_handle, &MOK_OWNER, EFI_NATIVE_INTERFACE, &shim_protocol_interface);
}

void
shim_protocol_uninstall(void)
{
	BS->UninstallProtocolInterface(shim_protocol_handle, &MOK_OWNER, &shim_protocol_interface);
}
