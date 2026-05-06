/*
 * Copyright (c) 2022 Winsider Seminars & Solutions, Inc.  All rights reserved.
 *
 * This file is part of System Informer.
 *
 * Authors:
 *
 *     dmex    2017-2023
 *
 */

#include "setup.h"
#include "..\thirdparty\miniz\miniz.h"

NTSTATUS SetupUseExistingKsi(
    _In_ PPH_STRING FileName,
    _In_ PVOID Buffer,
    _In_ ULONG BufferLength
    )
{
    NTSTATUS status;
    HANDLE fileHandle;
    IO_STATUS_BLOCK isb;
    LARGE_INTEGER fileSize;
    PVOID fileBuffer;
    ULONG fileLength;

    if (!PhDoesFileExistWin32(PhGetString(FileName)))
        return STATUS_NO_SUCH_FILE;

    status = PhCreateFileWin32Ex(
        &fileHandle,
        PhGetString(FileName),
        FILE_GENERIC_READ,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL
        );

    if (!NT_SUCCESS(status))
        return status;

    if (NT_SUCCESS(status = PhGetFileSize(fileHandle, &fileSize)))
    {
        if (fileSize.QuadPart > ULONG_MAX)
        {
            status = STATUS_FILE_TOO_LARGE;
            goto CleanupExit;
        }

        fileLength = fileSize.LowPart;

        if (fileLength == BufferLength)
        {
            fileBuffer = PhAllocate(fileLength);

            if (NT_SUCCESS(status = NtReadFile(fileHandle, NULL, NULL, NULL, &isb, fileBuffer, fileLength, NULL, NULL)))
            {
                if (isb.Information != fileLength)
                    status = STATUS_UNSUCCESSFUL;
            }

            if (NT_SUCCESS(status))
            {
                if (RtlEqualMemory(fileBuffer, Buffer, fileLength))
                    status = STATUS_SUCCESS;
                else
                    status = STATUS_UNSUCCESSFUL;
            }

            PhFree(fileBuffer);
        }
        else
        {
            status = STATUS_UNSUCCESSFUL;
        }
    }

CleanupExit:

    NtClose(fileHandle);

    return status;
}

NTSTATUS SetupUpdateKsi(
    _In_ PPH_SETUP_CONTEXT Context,
    _In_ PPH_STRING FileName,
    _In_ PVOID Buffer,
    _In_ ULONG BufferLength
    )
{
    NTSTATUS status;
    PPH_STRING oldFileName;

    oldFileName = PhConcatStrings(2, PhGetString(FileName), L".old");

    if (PhDoesFileExistWin32(PhGetString(oldFileName)))
    {
        if (!DeleteFile(PhGetString(oldFileName)))
        {
            status = PhGetLastWin32ErrorAsNtStatus();
            PhDereferenceObject(oldFileName);
            return status;
        }
    }

    if (MoveFile(PhGetString(FileName), PhGetString(oldFileName)))
    {
        status = SetupOverwriteFile(FileName, Buffer, BufferLength);

        if (NT_SUCCESS(status))
        {
            Context->NeedsReboot = TRUE;
        }
        else
        {
            MoveFile(PhGetString(oldFileName), PhGetString(FileName));
        }
    }
    else
    {
        status = PhGetLastWin32ErrorAsNtStatus();
    }

    PhDereferenceObject(oldFileName);

    return status;
}

static USHORT SetupGetCurrentArchitecture(
    VOID
    )
{
    static typeof(&IsWow64Process2) IsWow64Process2_I = NULL;
    USHORT processMachine;
    USHORT nativeMachine;
    SYSTEM_INFO info;

    if (!IsWow64Process2_I)
        IsWow64Process2_I = PhGetModuleProcAddress(L"kernel32.dll", "IsWow64Process2");

    if (IsWow64Process2_I && IsWow64Process2_I(NtCurrentProcess(), &processMachine, &nativeMachine))
    {
        switch (nativeMachine)
        {
        case IMAGE_FILE_MACHINE_I386:
            return PROCESSOR_ARCHITECTURE_INTEL;
        case IMAGE_FILE_MACHINE_AMD64:
            return PROCESSOR_ARCHITECTURE_AMD64;
        case IMAGE_FILE_MACHINE_ARM64:
            return PROCESSOR_ARCHITECTURE_ARM64;
        }
    }

    GetNativeSystemInfo(&info);

    return info.wProcessorArchitecture;
}

_Function_class_(USER_THREAD_START_ROUTINE)
NTSTATUS CALLBACK SetupExtractBuild(
    _In_ PPH_SETUP_CONTEXT Context
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG resourceLength;
    PVOID resourceBuffer = NULL;
    ULONG64 totalLength = 0;
    ULONG64 currentLength = 0;
    mz_zip_archive zipFileArchive = { 0 };
    PPH_STRING extractPath = NULL;
    USHORT nativeArchitecture;
    PPH_LIST stagedFiles = NULL;

    status = PhLoadResource(
        NtCurrentImageBase(),
        MAKEINTRESOURCE(IDR_BIN_DATA),
        RT_RCDATA,
        &resourceLength,
        &resourceBuffer
        );

    if (!NT_SUCCESS(status))
        return status;

    if (!mz_zip_reader_init_mem(&zipFileArchive, resourceBuffer, resourceLength, 0))
    {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    nativeArchitecture = SetupGetCurrentArchitecture();
    stagedFiles = PhCreateList(100);

    for (mz_uint i = 0; i < mz_zip_reader_get_num_files(&zipFileArchive); i++)
    {
        mz_zip_archive_file_stat zipFileStat;
        PPH_STRING fileName;

        if (!mz_zip_reader_file_stat(&zipFileArchive, i, &zipFileStat))
            continue;

        fileName = PhConvertUtf8ToUtf16(zipFileStat.m_filename);

        if (PhFindStringInString(fileName, 0, L"SystemInformer.exe.settings.xml") != SIZE_MAX)
        {
            PhDereferenceObject(fileName);
            continue;
        }
        if (PhFindStringInString(fileName, 0, L"usernotesdb.xml") != SIZE_MAX)
        {
            PhDereferenceObject(fileName);
            continue;
        }

        if (nativeArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
        {
            if (PhStartsWithString2(fileName, L"i386\\", TRUE) ||
                PhStartsWithString2(fileName, L"arm64\\", TRUE))
            {
                PhDereferenceObject(fileName);
                continue;
            }
        }
        else if (nativeArchitecture == PROCESSOR_ARCHITECTURE_ARM64)
        {
            if (PhStartsWithString2(fileName, L"i386\\", TRUE) ||
                PhStartsWithString2(fileName, L"amd64\\", TRUE))
            {
                PhDereferenceObject(fileName);
                continue;
            }
        }
        else
        {
            if (PhStartsWithString2(fileName, L"amd64\\", TRUE) ||
                PhStartsWithString2(fileName, L"arm64\\", TRUE))
            {
                PhDereferenceObject(fileName);
                continue;
            }
        }

        totalLength += zipFileStat.m_uncomp_size;
        PhDereferenceObject(fileName);
    }

    SendMessage(Context->DialogHandle, TDM_SET_MARQUEE_PROGRESS_BAR, FALSE, 0);

    // Phase 1: Extract and stage
    for (mz_uint i = 0; i < mz_zip_reader_get_num_files(&zipFileArchive); i++)
    {
        PVOID buffer = NULL;
        size_t zipFileBufferLength = 0;
        PPH_STRING fileName = NULL;
        mz_ulong zipFileCrc32 = 0;
        mz_zip_archive_file_stat zipFileStat;

        if (!mz_zip_reader_file_stat(&zipFileArchive, i, &zipFileStat))
            continue;

        fileName = PhConvertUtf8ToUtf16(zipFileStat.m_filename);

        if (PhFindStringInString(fileName, 0, L"SystemInformer.exe.settings.xml") != SIZE_MAX)
        {
            PhDereferenceObject(fileName);
            continue;
        }
        if (PhFindStringInString(fileName, 0, L"usernotesdb.xml") != SIZE_MAX)
        {
            PhDereferenceObject(fileName);
            continue;
        }

        if (nativeArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
        {
            if (PhStartsWithString2(fileName, L"i386\\", TRUE) ||
                PhStartsWithString2(fileName, L"arm64\\", TRUE))
            {
                PhDereferenceObject(fileName);
                continue;
            }

            if (PhStartsWithString2(fileName, L"amd64\\", TRUE))
                PhMoveReference(&fileName, PhSubstring(fileName, 6, (fileName->Length / sizeof(WCHAR)) - 6));
        }
        else if (nativeArchitecture == PROCESSOR_ARCHITECTURE_ARM64)
        {
            if (PhStartsWithString2(fileName, L"i386\\", TRUE) ||
                PhStartsWithString2(fileName, L"amd64\\", TRUE))
            {
                PhDereferenceObject(fileName);
                continue;
            }

            if (PhStartsWithString2(fileName, L"arm64\\", TRUE))
                PhMoveReference(&fileName, PhSubstring(fileName, 6, (fileName->Length / sizeof(WCHAR)) - 6));
        }
        else
        {
            if (PhStartsWithString2(fileName, L"amd64\\", TRUE) ||
                PhStartsWithString2(fileName, L"arm64\\", TRUE))
            {
                PhDereferenceObject(fileName);
                continue;
            }

            if (PhStartsWithString2(fileName, L"i386\\", TRUE))
                PhMoveReference(&fileName, PhSubstring(fileName, 5, (fileName->Length / sizeof(WCHAR)) - 5));
        }

        if (!(buffer = mz_zip_reader_extract_to_heap(&zipFileArchive, zipFileStat.m_file_index, &zipFileBufferLength, 0)))
        {
            PhDereferenceObject(fileName);
            status = STATUS_NO_MEMORY;
            goto CleanupExit;
        }

        if ((zipFileCrc32 = mz_crc32(zipFileCrc32, buffer, (mz_uint)zipFileBufferLength)) != zipFileStat.m_crc32)
        {
            mz_free(buffer);
            PhDereferenceObject(fileName);
            status = STATUS_CRC_ERROR;
            goto CleanupExit;
        }

        PhClearReference(&extractPath);
        extractPath = PhConcatStringRef3(
            &Context->SetupInstallPath->sr,
            &PhNtPathSeparatorString,
            &fileName->sr
            );
        
        PhDereferenceObject(fileName);

        if (!NT_SUCCESS(status = PhCreateDirectoryFullPathWin32(&extractPath->sr)))
        {
            mz_free(buffer);
            goto CleanupExit;
        }

        if (PhEndsWithString2(extractPath, L"\\ksi.dll", FALSE))
        {
            ULONG attempts = 5;

            do
            {
                if (NT_SUCCESS(status = SetupUseExistingKsi(extractPath, buffer, (ULONG)zipFileBufferLength)))
                    break;
                if (NT_SUCCESS(status = SetupOverwriteFile(extractPath, buffer, (ULONG)zipFileBufferLength)))
                    break;
                if (NT_SUCCESS(status = SetupUpdateKsi(Context, extractPath, buffer, (ULONG)zipFileBufferLength)))
                    break;

                PhDelayExecution(1000);
            } while (--attempts);
        }
        else
        {
            if (NT_SUCCESS(status = SetupWriteFileAtomic(Context, extractPath, buffer, (ULONG)zipFileBufferLength)))
            {
                PhAddItemList(stagedFiles, PhReferenceObject(extractPath));
            }
        }

        mz_free(buffer);

        if (!NT_SUCCESS(status))
            goto CleanupExit;

        currentLength += zipFileBufferLength;

        {
            ULONG64 percent = 50 * currentLength / totalLength;
            PH_FORMAT format[7];
            WCHAR string[MAX_PATH];
            PPH_STRING baseName = PhGetBaseName(extractPath);

            PhInitFormatS(&format[0], L"Extracting: ");
            PhInitFormatS(&format[1], PhGetStringOrEmpty(baseName));

            if (PhFormatToBuffer(format, 2, string, sizeof(string), NULL))
            {
                SendMessage(Context->DialogHandle, TDM_UPDATE_ELEMENT_TEXT, TDE_MAIN_INSTRUCTION, (LPARAM)string);
            }

            PhInitFormatS(&format[0], L"Progress: ");
            PhInitFormatSize(&format[1], currentLength);
            PhInitFormatS(&format[2], L" of ");
            PhInitFormatSize(&format[3], totalLength);
            PhInitFormatS(&format[4], L" (");
            PhInitFormatI64U(&format[5], percent);
            PhInitFormatS(&format[6], L"%)");

            if (PhFormatToBuffer(format, ARRAYSIZE(format), string, sizeof(string), NULL))
            {
                SendMessage(Context->DialogHandle, TDM_UPDATE_ELEMENT_TEXT, TDE_CONTENT, (LPARAM)string);
            }

            SendMessage(Context->DialogHandle, TDM_SET_PROGRESS_BAR_POS, (WPARAM)(INT)percent, 0);

            if (baseName)
                PhDereferenceObject(baseName);
        }
    }

    // Phase 2: Commit
    for (ULONG i = 0; i < stagedFiles->Count; i++)
    {
        PPH_STRING file = stagedFiles->Items[i];
        ULONG64 percent = stagedFiles->Count ? 50 + (50 * (i + 1) / stagedFiles->Count) : 100;
        PH_FORMAT format[2];
        WCHAR string[MAX_PATH];
        PPH_STRING baseName = PhGetBaseName(file);

        if (!NT_SUCCESS(status = SetupCommitFile(Context, file)))
        {
            if (baseName) PhDereferenceObject(baseName);
            goto CleanupExit;
        }

        PhInitFormatS(&format[0], L"Finalizing: ");
        PhInitFormatS(&format[1], PhGetStringOrEmpty(baseName));

        if (PhFormatToBuffer(format, 2, string, sizeof(string), NULL))
        {
            SendMessage(Context->DialogHandle, TDM_UPDATE_ELEMENT_TEXT, TDE_MAIN_INSTRUCTION, (LPARAM)string);
        }

        SendMessage(Context->DialogHandle, TDM_SET_PROGRESS_BAR_POS, (WPARAM)(INT)percent, 0);

        if (baseName)
            PhDereferenceObject(baseName);
    }

CleanupExit:

    if (stagedFiles)
    {
        if (NT_SUCCESS(status))
        {
            for (ULONG i = 0; i < stagedFiles->Count; i++)
                SetupFinalizeFile(Context, stagedFiles->Items[i]);
        }
        else
        {
            for (ULONG i = 0; i < stagedFiles->Count; i++)
                SetupRollbackFile(Context, stagedFiles->Items[i]);
        }

        for (ULONG i = 0; i < stagedFiles->Count; i++)
            PhDereferenceObject(stagedFiles->Items[i]);
        PhDereferenceObject(stagedFiles);
    }

    mz_zip_reader_end(&zipFileArchive);

    if (extractPath)
        PhDereferenceObject(extractPath);

    return status;
}
