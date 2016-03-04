#include <efi.h>

#ifndef BUILD_EFI
#ifdef CONFIG_arm
/* FIXME:
 * arm efi leaves a visibilit pragma pushed that won't work for
 * non efi programs, so eliminate it */
#pragma GCC visibility pop
#endif
const char *guid_to_str(EFI_GUID *guid);
int str_to_guid(const char *str, EFI_GUID *guid);
int compare_guid(EFI_GUID *g1, EFI_GUID *g2);
EFI_GUID *get_owner_guid(char *var);
#endif

extern EFI_GUID GV_GUID;
extern EFI_GUID SIG_DB;
extern EFI_GUID X509_GUID;
extern EFI_GUID RSA2048_GUID;
extern EFI_GUID PKCS7_GUID;
extern EFI_GUID IMAGE_PROTOCOL;
extern EFI_GUID SIMPLE_FS_PROTOCOL;
extern EFI_GUID EFI_CERT_SHA256_GUID;
extern EFI_GUID MOK_OWNER;
extern EFI_GUID SECURITY_PROTOCOL_GUID;
extern EFI_GUID SECURITY2_PROTOCOL_GUID;
extern EFI_GUID SECURE_VARIABLE_GUID;
extern EFI_GUID PKCS7_VERIFY_PROTOCOL_GUID;
extern EFI_GUID EFI_CERT_SHA1_GUID;
extern EFI_GUID EFI_CERT_SHA224_GUID;
extern EFI_GUID EFI_CERT_SHA384_GUID;
extern EFI_GUID EFI_CERT_SHA512_GUID;
extern EFI_GUID *allowed_hashes[];
extern UINTN allowed_hashes_size;

