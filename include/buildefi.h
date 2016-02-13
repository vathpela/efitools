#ifndef _BUILDEFI_H
#define _BUILDEFI_H

#ifndef BUILD_EFI
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define Print(...) printf("%ls", __VA_ARGS__)
#define AllocatePool(x) malloc(x)
#define CopyMem(d, s, l) memcpy(d, s, l)
#define ZeroMem(s, l) memset(s, 0, l)
#define FreePool(s) free(s)
#endif

#endif /* _BUILDEFI_H */
