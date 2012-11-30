/*
 * Copyright 2012 <James.Bottomley@HansenPartnership.com>
 *
 * see COPYING file
 *
 * --
 *
 * generate_path is a cut and paste from
 *  
 *   git://github.com/mjg59/shim.git
 *
 * Code Copyright 2012 Red Hat, Inc <mjg@redhat.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */




#include <efi.h>
#include <efilib.h>

#include <console.h>
#include <simple_file.h>
#include <efiauthenticated.h>

static EFI_GUID IMAGE_PROTOCOL = LOADED_IMAGE_PROTOCOL;
static EFI_GUID SIMPLE_FS_PROTOCOL = SIMPLE_FILE_SYSTEM_PROTOCOL;
static EFI_GUID FILE_INFO = EFI_FILE_INFO_ID;
static EFI_GUID FS_INFO = EFI_FILE_SYSTEM_INFO_ID;

EFI_STATUS
generate_path(CHAR16* name, EFI_LOADED_IMAGE *li, EFI_DEVICE_PATH **grubpath, CHAR16 **PathName)
{
	EFI_DEVICE_PATH *devpath;
	EFI_HANDLE device;
	FILEPATH_DEVICE_PATH *FilePath;
	int len;
	unsigned int pathlen = 0;
	EFI_STATUS efi_status = EFI_SUCCESS;

	device = li->DeviceHandle;
	devpath = li->FilePath;

	while (!IsDevicePathEnd(devpath) &&
	       !IsDevicePathEnd(NextDevicePathNode(devpath))) {
		FilePath = (FILEPATH_DEVICE_PATH *)devpath;
		len = StrLen(FilePath->PathName);

		pathlen += len;

		if (len == 1 && FilePath->PathName[0] == '\\') {
			devpath = NextDevicePathNode(devpath);
			continue;
		}

		/* If no leading \, need to add one */
		if (FilePath->PathName[0] != '\\')
			pathlen++;

		/* If trailing \, need to strip it */
		if (FilePath->PathName[len-1] == '\\')
			pathlen--;

		devpath = NextDevicePathNode(devpath);
	}

	*PathName = AllocatePool((pathlen + 1 + StrLen(name))*sizeof(CHAR16));

	if (!*PathName) {
		Print(L"Failed to allocate path buffer\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto error;
	}

	*PathName[0] = '\0';
	devpath = li->FilePath;

	while (!IsDevicePathEnd(devpath) &&
	       !IsDevicePathEnd(NextDevicePathNode(devpath))) {
		CHAR16 *tmpbuffer;
		FilePath = (FILEPATH_DEVICE_PATH *)devpath;
		len = StrLen(FilePath->PathName);

		if (len == 1 && FilePath->PathName[0] == '\\') {
			devpath = NextDevicePathNode(devpath);
			continue;
		}

		tmpbuffer = AllocatePool((len + 1)*sizeof(CHAR16));

		if (!tmpbuffer) {
			Print(L"Unable to allocate temporary buffer\n");
			return EFI_OUT_OF_RESOURCES;
		}

		StrCpy(tmpbuffer, FilePath->PathName);

		/* If no leading \, need to add one */
		if (tmpbuffer[0] != '\\')
			StrCat(*PathName, L"\\");

		/* If trailing \, need to strip it */
		if (tmpbuffer[len-1] == '\\')
			tmpbuffer[len-1] = '\0';

		StrCat(*PathName, tmpbuffer);
		FreePool(tmpbuffer);
		devpath = NextDevicePathNode(devpath);
	}

	StrCat(*PathName, L"\\");
	StrCat(*PathName, name);

	*grubpath = FileDevicePath(device, *PathName);

error:
	return efi_status;
}

EFI_STATUS
simple_file_open_by_handle(EFI_HANDLE device, CHAR16 *name, EFI_FILE **file, UINT64 mode)
{
	EFI_STATUS efi_status;
	EFI_FILE_IO_INTERFACE *drive;
	EFI_FILE *root;

	efi_status = uefi_call_wrapper(BS->HandleProtocol, 3, device,
				       &SIMPLE_FS_PROTOCOL, &drive);

	if (efi_status != EFI_SUCCESS) {
		Print(L"Unable to find simple file protocol\n");
		goto error;
	}

	efi_status = uefi_call_wrapper(drive->OpenVolume, 2, drive, &root);

	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to open drive volume\n");
		goto error;
	}

	efi_status = uefi_call_wrapper(root->Open, 5, root, file, name,
				       mode, 0);

 error:
	return efi_status;
}

EFI_STATUS
simple_file_open(EFI_HANDLE image, CHAR16 *name, EFI_FILE **file, UINT64 mode)
{
	EFI_STATUS efi_status;
	EFI_HANDLE device;
	EFI_LOADED_IMAGE *li;
	EFI_DEVICE_PATH *loadpath = NULL;
	CHAR16 *PathName = NULL;

	efi_status = uefi_call_wrapper(BS->HandleProtocol, 3, image,
				       &IMAGE_PROTOCOL, &li);

	if (efi_status != EFI_SUCCESS)
		return simple_file_open_by_handle(image, name, file, mode);

	efi_status = generate_path(name, li, &loadpath, &PathName);

	if (efi_status != EFI_SUCCESS) {
		Print(L"Unable to generate load path for %s\n", name);
		goto error;
	}

	device = li->DeviceHandle;

	return simple_file_open_by_handle(device, PathName, file, mode);

 error:
	//if (PathName)
	//	FreePool(PathName);

	return efi_status;
}

EFI_STATUS
simple_dir_read_all_by_handle(EFI_HANDLE image, EFI_FILE *file, CHAR16* name, EFI_FILE_INFO **entries,
		    int *count)
{
	EFI_STATUS status;
	char buf[4096];
	UINTN size = sizeof(buf);
	EFI_FILE_INFO *fi = (void *)buf;
	
	status = uefi_call_wrapper(file->GetInfo, 4, file, &FILE_INFO,
				   &size, fi);
	if (status != EFI_SUCCESS) {
		Print(L"Failed to get file info\n");
		goto out;
	}
	if ((fi->Attribute & EFI_FILE_DIRECTORY) == 0) {
		Print(L"Not a directory %s\n", name);
		status = EFI_INVALID_PARAMETER;
		goto out;
	}
	size = 0;
	*count = 0;
	for (;;) {
		UINTN len = sizeof(buf);
		status = uefi_call_wrapper(file->Read, 3, file, &len, buf);
		if (status != EFI_SUCCESS || len == 0)
			break;
		(*count)++;
		size += len;
	}
	uefi_call_wrapper(file->SetPosition, 2, file, 0);

	char *ptr = AllocatePool(size);
	*entries = (EFI_FILE_INFO *)ptr;
	if (!*entries)
		return EFI_OUT_OF_RESOURCES;
	int i;
	for (i = 0; i < *count; i++) {
		int len = size;
		uefi_call_wrapper(file->Read, 3, file, &len, ptr);
		ptr += len;
		size -= len;
	}
	status = EFI_SUCCESS;
 out:
	simple_file_close(file);
	if (status != EFI_SUCCESS && *entries) {
		FreePool(*entries);
		*entries = NULL;
	}
	return status;
}

EFI_STATUS
simple_dir_read_all(EFI_HANDLE image, CHAR16 *name, EFI_FILE_INFO **entries,
		    int *count)
{
	EFI_FILE *file;
	EFI_STATUS status;

	status = simple_file_open(image, name, &file, EFI_FILE_MODE_READ);
	if (status != EFI_SUCCESS) {
		Print(L"failed to open file %s: %d\n", name, status);
		return status;
	}

	return simple_dir_read_all_by_handle(image, file, name, entries, count);
}

EFI_STATUS
simple_file_read_all(EFI_FILE *file, UINTN *size, void **buffer)
{
	EFI_STATUS efi_status;
	EFI_FILE_INFO *fi;
	char buf[1024];

	*size = sizeof(buf);
	fi = (void *)buf;
	

	efi_status = uefi_call_wrapper(file->GetInfo, 4, file, &FILE_INFO,
				       size, fi);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to get file info\n");
		return efi_status;
	}

	*size = fi->FileSize;

	*buffer = AllocatePool(*size);
	if (!*buffer) {
		Print(L"Failed to allocate buffer of size %d\n", *size);
		return EFI_OUT_OF_RESOURCES;
	}
	efi_status = uefi_call_wrapper(file->Read, 3, file, size, *buffer);

	return efi_status;
}


EFI_STATUS
simple_file_write_all(EFI_FILE *file, UINTN size, void *buffer)
{
	EFI_STATUS efi_status;

	efi_status = uefi_call_wrapper(file->Write, 3, file, &size, buffer);

	return efi_status;
}

void
simple_file_close(EFI_FILE *file)
{
	uefi_call_wrapper(file->Close, 1, file);
}

EFI_STATUS
simple_volume_selector(CHAR16 **title, CHAR16 **selected, EFI_HANDLE *h)
{
	UINTN count, i;
	EFI_HANDLE *vol_handles = NULL;
	EFI_STATUS status;
	CHAR16 **entries;
	int val;

	uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
			  &SIMPLE_FS_PROTOCOL, NULL, &count, &vol_handles);

	if (!count || !vol_handles)
		return EFI_NOT_FOUND;

	entries = AllocatePool(sizeof(CHAR16 *) * (count+1));
	if (!entries)
		return EFI_OUT_OF_RESOURCES;

	for (i = 0; i < count; i++) {
		char buf[4096];
		UINTN size = sizeof(buf);
		EFI_FILE_SYSTEM_INFO *fi = (void *)buf;
		EFI_FILE *root;
		CHAR16 *name;
		EFI_FILE_IO_INTERFACE *drive;

		status = uefi_call_wrapper(BS->HandleProtocol, 3,
					   vol_handles[i],
					   &SIMPLE_FS_PROTOCOL, &drive);
		if (status != EFI_SUCCESS || !drive)
			continue;

		status = uefi_call_wrapper(drive->OpenVolume, 2, drive, &root);
		if (status != EFI_SUCCESS)
			continue;

		status = uefi_call_wrapper(root->GetInfo, 4, root, &FS_INFO,
					   &size, fi);
		if (status != EFI_SUCCESS)
			continue;

		name = fi->VolumeLabel;
		
		if (!name || StrLen(name) == 0 || StrCmp(name, L" ") == 0) 
			name = DevicePathToStr(DevicePathFromHandle(vol_handles[i]));

		entries[i] = AllocatePool((StrLen(name) + 2) * sizeof(CHAR16));
		if (!entries[i])
			break;
		StrCpy(entries[i], name);
	}
	entries[i] = NULL;

	val = console_select(title, entries, 0);

	if (val >= 0) {
		*selected = AllocatePool((StrLen(entries[val]) + 1) * sizeof(CHAR16));
		if (*selected) {
			StrCpy(*selected , entries[val]);
		}
		*h = vol_handles[val];
	} else {
		*selected = NULL;
		*h = 0;
	}

	for (i = 0; i < count; i++) {
		if (entries[i])
			FreePool(entries[i]);
	}
	FreePool(entries);
	FreePool(vol_handles);

	
	return EFI_SUCCESS;
}

EFI_STATUS
simple_dir_filter(EFI_HANDLE image, CHAR16 *name, CHAR16 *filter,
		  CHAR16 ***result, int *count, EFI_FILE_INFO **entries)
{
	EFI_STATUS status;
	int tot, offs = StrLen(filter), i, c, filtercount = 1;
	EFI_FILE_INFO *next;
	void *ptr;
	CHAR16 *newfilter = AllocatePool((StrLen(filter) + 1) * sizeof(CHAR16)),
		**filterarr;

	if (!newfilter)
		return EFI_OUT_OF_RESOURCES;

	/* just in case efi ever stops writeable strings */
	StrCpy(newfilter, filter);

	for (i = 0; i < offs; i++) {
		if (filter[i] == '|')
			filtercount++;
	}
	filterarr = AllocatePool(filtercount * sizeof(void *));
	if (!filterarr)
		return EFI_OUT_OF_RESOURCES;
	c = 0;
	filterarr[c++] = newfilter;
	for (i = 0; i < offs; i++) {
		if (filter[i] == '|') {
			newfilter[i] = '\0';
			filterarr[c++] = &newfilter[i+1];
		}
	}

	*count = 0;

	status = simple_dir_read_all(image, name, entries, &tot);
		
	if (status != EFI_SUCCESS)
		goto out;
	ptr = next = *entries;

	for (i = 0; i < tot; i++) {
		int len = StrLen(next->FileName);

		for (c = 0; c < filtercount; c++) {
			offs = StrLen(filterarr[c]);

			if (StrCmp(&next->FileName[len - offs], filterarr[c]) == 0
			    || (next->Attribute & EFI_FILE_DIRECTORY)) {
				(*count)++;
				break;
			}
		}
		ptr += OFFSET_OF(EFI_FILE_INFO, FileName) + (len + 1)*sizeof(CHAR16);
		next = ptr;
	}
	*result = AllocatePool(((*count) + 1) * sizeof(void *));

	*count = 0;
	ptr = next = *entries;

	for (i = 0; i < tot; i++) {
		int len = StrLen(next->FileName);

		for (c = 0; c < filtercount; c++) {
			offs = StrLen(filterarr[c]);

			if (StrCmp(&next->FileName[len - offs], filterarr[c]) == 0) {
				(*result)[(*count)++] = next->FileName;
			} else if (next->Attribute & EFI_FILE_DIRECTORY) {
				(*result)[(*count)] = next->FileName;
				(*result)[(*count)][len] = '/';
				(*result)[(*count)++][len + 1] = '\0';
			} else {
				continue;
			}
			break;
		}

		ptr += OFFSET_OF(EFI_FILE_INFO, FileName) + (len + 1)*sizeof(CHAR16);
		next = ptr;
	}
	(*result)[*count] = NULL;
	status = EFI_SUCCESS;

 out:
	if (status != EFI_SUCCESS) {
		if (*entries)
			FreePool(*entries);
		*entries = NULL;
		if (*result)
			FreePool(*result);
		*result = NULL;
	}
	return status;
}

void
simple_file_selector(EFI_HANDLE *im, CHAR16 **title, CHAR16 *name,
		     CHAR16 *filter, CHAR16 **result)
{
	EFI_STATUS status;
	CHAR16 **entries;
	EFI_FILE_INFO *dmp;
	int count, select, len;
	CHAR16 *newname, *selected;

	*result = NULL;
	if (!name)
		name = L"\\";
	if (!*im) {
		EFI_HANDLE h;
		CHAR16 *volname;

		simple_volume_selector(title, &volname, &h);
		if (!volname)
			return;
		FreePool(volname);
		*im = h;
	}

	newname = AllocatePool((StrLen(name) + 1)*sizeof(CHAR16));
	if (!newname)
		return;

	StrCpy(newname, name);
	name = newname;

 redo:
	status = simple_dir_filter(*im, name, filter, &entries, &count, &dmp);

	if (status != EFI_SUCCESS)
		goto out_free_name;

	select = console_select(title, entries, 0);
	if (select < 0)
		/* ESC key */
		goto out_free;
	selected = entries[select];
	FreePool(entries);
	entries = NULL;
	/* note that memory used by selected is valid until dmp is freed */
	len = StrLen(selected);
	if (selected[len - 1] == '/') {
		CHAR16 *newname;

		/* stay where we are */
		if (StrCmp(selected, L"./") == 0) {
			FreePool(dmp);
			goto redo;
		} else if (StrCmp(selected, L"../") == 0) {
			int i;

			FreePool(dmp);

			for (i = StrLen(name); i > 0; --i) {
				if (name[i] == '\\')
					break;
			}
			if (i == 0)
				i = 1;
			name[i] = '\0';
			goto redo;
		}
		newname = AllocatePool((StrLen(name) + len + 2)*sizeof(CHAR16));
		if (!newname)
			goto out_free;
		StrCpy(newname, name);
			
		if (name[StrLen(name) - 1] != '\\')
			StrCat(newname, L"\\");
		StrCat(newname, selected);
		/* remove trailing / */
		newname[StrLen(newname) - 1] = '\0';
		FreePool(dmp);
		FreePool(name);
		name = newname;
		goto redo;
	}
	*result = AllocatePool((StrLen(name) + len + 2)*sizeof(CHAR16));
	if (*result) {
		StrCpy(*result, name);
		if (name[StrLen(name) - 1] != '\\')
			StrCat(*result, L"\\");
		StrCat(*result, selected);
	}

 out_free:
	FreePool(dmp);
	if (entries)
		FreePool(entries);
 out_free_name:
	FreePool(name);
}
