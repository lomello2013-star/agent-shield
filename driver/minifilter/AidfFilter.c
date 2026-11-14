/*
 * AidfFilter — minimal minifilter with a user-mode policy channel.
 *
 * User mode sends a substring policy over the Filter Manager communication
 * port "\AidfFilterPort". The kernel blocks create/write when the file name
 * contains that substring. Empty policy = no block (fail-open until armed).
 *
 * This is a *test-signed lab driver*: production needs EV signing + WHQL.
 */

#include <fltkernel.h>

#define AIDF_POLICY_MAX_CHARS 255

static PFLT_FILTER gFilter = NULL;
static PFLT_PORT gServerPort = NULL;
static PFLT_PORT gClientPort = NULL;
static FAST_MUTEX gPolicyLock;
static WCHAR gPolicy[AIDF_POLICY_MAX_CHARS + 1];
static USHORT gPolicyChars = 0;
static SECURITY_DESCRIPTOR gPortSd;
static UCHAR gPortAcl[256];
static UCHAR gSystemSid[SECURITY_MAX_SID_SIZE];
static UCHAR gAdminSid[SECURITY_MAX_SID_SIZE];

typedef struct _AIDF_POLICY_MESSAGE {
    ULONG Length;       /* bytes in Text */
    WCHAR Text[1];
} AIDF_POLICY_MESSAGE;

static BOOLEAN
AidfNameContains(
    _In_ PCUNICODE_STRING Name,
    _In_reads_(PatternChars) const WCHAR *Pattern,
    _In_ USHORT PatternChars
    )
{
    USHORT chars;
    USHORT i, j;

    if (Name == NULL || Name->Buffer == NULL || PatternChars == 0 ||
        Name->Length < PatternChars * sizeof(WCHAR)) {
        return FALSE;
    }
    chars = (USHORT)(Name->Length / sizeof(WCHAR));
    for (i = 0; i + PatternChars <= chars; i++) {
        BOOLEAN match = TRUE;
        for (j = 0; j < PatternChars; j++) {
            WCHAR c = Name->Buffer[i + j];
            if (c >= L'A' && c <= L'Z') {
                c = (WCHAR)(c + (L'a' - L'A'));
            }
            if (c != Pattern[j]) {
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

static BOOLEAN
AidfMatchesPolicy(_In_ PCUNICODE_STRING Name)
{
    WCHAR policy[AIDF_POLICY_MAX_CHARS + 1];
    USHORT chars;
    BOOLEAN match;

    ExAcquireFastMutex(&gPolicyLock);
    chars = gPolicyChars;
    if (chars > 0) {
        RtlCopyMemory(policy, gPolicy, chars * sizeof(WCHAR));
    }
    ExReleaseFastMutex(&gPolicyLock);

    if (chars == 0) {
        return FALSE;
    }
    match = AidfNameContains(Name, policy, chars);
    RtlSecureZeroMemory(policy, sizeof(policy));
    return match;
}

static NTSTATUS
AidfBuildPortSecurityDescriptor(void)
{
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID systemSid = (PSID)gSystemSid;
    PSID adminSid = (PSID)gAdminSid;
    PACL acl = (PACL)gPortAcl;
    ULONG aclSize;
    NTSTATUS status;

    RtlZeroMemory(gSystemSid, sizeof(gSystemSid));
    RtlZeroMemory(gAdminSid, sizeof(gAdminSid));
    status = RtlInitializeSid(systemSid, &ntAuth, 1);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    *RtlSubAuthoritySid(systemSid, 0) = SECURITY_LOCAL_SYSTEM_RID;
    status = RtlInitializeSid(adminSid, &ntAuth, 2);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    *RtlSubAuthoritySid(adminSid, 0) = SECURITY_BUILTIN_DOMAIN_RID;
    *RtlSubAuthoritySid(adminSid, 1) = DOMAIN_ALIAS_RID_ADMINS;

    aclSize = sizeof(ACL)
        + (sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG) + RtlLengthSid(systemSid))
        + (sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG) + RtlLengthSid(adminSid));
    if (aclSize > sizeof(gPortAcl)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = RtlCreateAcl(acl, sizeof(gPortAcl), ACL_REVISION);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = RtlAddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, systemSid);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = RtlAddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, adminSid);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = RtlCreateSecurityDescriptor(&gPortSd, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return RtlSetDaclSecurityDescriptor(&gPortSd, TRUE, acl, FALSE);
}

static NTSTATUS
AidfConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    )
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    if (gClientPort != NULL) {
        return STATUS_CONNECTION_COUNT_LIMIT;
    }
    gClientPort = ClientPort;
    *ConnectionPortCookie = NULL;
    return STATUS_SUCCESS;
}

static VOID
AidfDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    gClientPort = NULL;
}

static NTSTATUS
AidfMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    AIDF_POLICY_MESSAGE *msg;
    ULONG bytes;

    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    *ReturnOutputBufferLength = 0;
    if (InputBuffer == NULL || InputBufferLength < sizeof(ULONG)) {
        return STATUS_INVALID_PARAMETER;
    }
    msg = (AIDF_POLICY_MESSAGE *)InputBuffer;
    bytes = msg->Length;
    if (bytes > AIDF_POLICY_MAX_CHARS * sizeof(WCHAR) ||
        bytes > InputBufferLength - sizeof(ULONG)) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireFastMutex(&gPolicyLock);
    RtlZeroMemory(gPolicy, sizeof(gPolicy));
    if (bytes > 0) {
        RtlCopyMemory(gPolicy, msg->Text, bytes);
    }
    gPolicyChars = (USHORT)(bytes / sizeof(WCHAR));
    ExReleaseFastMutex(&gPolicyLock);
    return STATUS_SUCCESS;
}

static NTSTATUS
AidfUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    if (gServerPort != NULL) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
    }
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
        block = AidfMatchesPolicy(&FltObjects->FileObject->FileName);
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
            block = AidfMatchesPolicy(&nameInfo->Name);
        }
        FltReleaseFileNameInformation(nameInfo);
    } else if (FltObjects != NULL && FltObjects->FileObject != NULL) {
        block = AidfMatchesPolicy(&FltObjects->FileObject->FileName);
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
    UNICODE_STRING portName = RTL_CONSTANT_STRING(L"\\AidfFilterPort");
    OBJECT_ATTRIBUTES oa;

    UNREFERENCED_PARAMETER(RegistryPath);

    ExInitializeFastMutex(&gPolicyLock);
    RtlZeroMemory(gPolicy, sizeof(gPolicy));
    gPolicyChars = 0;

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

    status = AidfBuildPortSecurityDescriptor();
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
        return status;
    }
    InitializeObjectAttributes(&oa, &portName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &gPortSd);
    status = FltCreateCommunicationPort(gFilter, &gServerPort, &oa, NULL,
                                        AidfConnect, AidfDisconnect, AidfMessage, 1);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
        return status;
    }
    return STATUS_SUCCESS;
}
