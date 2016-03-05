#ifndef _SHIM_PROTOCOL_H
#define _SHIM_PROTOCOL_H

#include <PeImage.h>
#include <pkcs7verify.h>

typedef
EFI_STATUS
(*EFI_SHIM_LOCK_VERIFY) (
	IN VOID *buffer,
	IN UINT32 size
	);

typedef
EFI_STATUS
(*EFI_SHIM_LOCK_HASH) (
	IN char *data,
	IN int datasize,
	PE_COFF_LOADER_IMAGE_CONTEXT *context,
	UINT8 *sha256hash,
	UINT8 *sha1hash
	);

typedef
EFI_STATUS
(*EFI_SHIM_LOCK_CONTEXT) (
	IN VOID *data,
	IN unsigned int datasize,
	PE_COFF_LOADER_IMAGE_CONTEXT *context
	);

typedef struct _SHIM_LOCK {
	EFI_SHIM_LOCK_VERIFY Verify;
	EFI_SHIM_LOCK_HASH Hash;
	EFI_SHIM_LOCK_CONTEXT Context;
} SHIM_LOCK;


EFI_STATUS shim_protocol_install(void);
void shim_protocol_uninstall(void);

#endif /* _SHIM_PROTOCOL_H */
