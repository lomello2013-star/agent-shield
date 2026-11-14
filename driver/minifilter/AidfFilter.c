/*
 * AidfFilter — minimal minifilter for the driver contour.
 *
 * Scope: deny IRP_MJ_WRITE to any path containing "\protected\".
 * This is a *test-signed lab driver*: it demonstrates the kernel contract,
 * load/unload and a real block. Production needs EV signing + WHQL.
 */

#include <fltkernel.h>

static PFLT_FILTER gFilter = NULL;

/* Case-insensitive substring check for "\protected\" without relying on
 * null-terminated UNICODE_STRINGs or FsRtl name patterns. */
static BOOLEAN
AidfContainsProtected(_In_ PCUNICODE_STRING Name)
{
    static const WCHAR pattern[] = L"\\protected\\";
    USHORT patternChars = (USHORT)(sizeof(pattern) / sizeof(WCHAR) - 1);
    USHORT chars;
    USHORT i, j;

    if (Name == NULL || Name->Buffer == NULL || Name->Length < patternChars * sizeof(WCHAR)) {
        return FALSE;
    }
    chars = (USHORT)(Name->Length / sizeof(WCHAR));
    for (i = 0; i + patternChars <= chars; i++) {
        BOOLEAN match = TRUE;
        for (j = 0; j < patternChars; j++) {
            WCHAR c = Name->Buffer[i + j];
            if (c >= L'A' && c <= L'Z') {
                c = (WCHAR)(c + (L'a' - L'A'));
            }
            if (c != pattern[j]) {
                match = FALSE;
                break;
            }
        }
        if (match) {
            return TRUE;
        }
    }
    return FALSE;
}

static NTSTATUS
AidfUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    if (gFilter != NULL) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
    }
    return STATUS_SUCCESS;
}

static FLT_PREOP_CALLBACK_STATUS
AidfPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    ACCESS_MASK desired;
    BOOLEAN block = FALSE;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->Iopb->Parameters.Create.SecurityContext == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    desired = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    if ((desired & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | DELETE)) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (FltObjects != NULL && FltObjects->FileObject != NULL) {
        block = AidfContainsProtected(&FltObjects->FileObject->FileName);
    }
    if (block) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS
AidfPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    BOOLEAN block = FALSE;

    UNREFERENCED_PARAMETER(CompletionContext);

    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(nameInfo);
        if (NT_SUCCESS(status)) {
            block = AidfContainsProtected(&nameInfo->Name);
        }
        FltReleaseFileNameInformation(nameInfo);
    } else if (FltObjects != NULL && FltObjects->FileObject != NULL) {
        /* Fallback: volume-relative name is enough for a suffix check. */
        block = AidfContainsProtected(&FltObjects->FileObject->FileName);
    }

    if (block) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static const FLT_OPERATION_REGISTRATION gCallbacks[] = {
    { IRP_MJ_CREATE, 0, AidfPreCreate, NULL },
    { IRP_MJ_WRITE, 0, AidfPreWrite, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION gRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    gCallbacks,
    AidfUnload,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    status = FltRegisterFilter(DriverObject, &gRegistration, &gFilter);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltStartFiltering(gFilter);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}
