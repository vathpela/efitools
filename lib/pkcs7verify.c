#include <efi.h>
#include <efilib.h>

#include <efiauthenticated.h>
#include <guid.h>
#include <pkcs7verify.h>
#include <execute.h>

CHAR16 *p7bin = L"\\Pkcs7VerifyDxe.efi";

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

	return status;
}
