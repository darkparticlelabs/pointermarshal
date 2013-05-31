using System;
using System.IO;
using System.Net;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace WinapiMarshal
{
    /*
     * All WinAPI functions which have been imported via loadlibrary, getprocaddress have to have delegates to reference
     */
    #region Delegates
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate ulong DelegateGetTickCount64();

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate uint DelegateGetTickCount();

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate uint DelegateMsiGetPatchInfoEx(
            String szPatchCode,
            String szProductCode,
            String szUserSid, //pass 'null' to omit.
            MSIINSTALLCONTEXT dwContext,
            String szProperty,
            [Out] StringBuilder lpValue,
            ref uint pcchValue
        );
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate uint DelegateMsiEnumPatchesEx(string szProductCode,
            string szUserSid,
            uint dwContext,
            uint dwFilter,
            uint dwIndex,
            StringBuilder szPatchCode,
            StringBuilder szTargetProductCode,
            out object pdwTargetProductContext,
            StringBuilder szTargetUserSid,
            ref uint pcchTargetUserSid);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate bool DelegateEnumServicesStatusEx(IntPtr hSCManager,
            int infoLevel, int dwServiceType,
            int dwServiceState, IntPtr lpServices, UInt32 cbBufSize,
            out uint pcbBytesNeeded, out uint lpServicesReturned,
            ref uint lpResumeHandle, string pszGroupName);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate IntPtr DelegateOpenSCManager(string machineName, string databaseName, uint dwAccess);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate bool DelegateCloseServiceHandle(IntPtr hSCObject);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate bool DelegateReadFile(IntPtr hFile, byte[] lpBuffer,
           uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateGetIpNetTable(IntPtr pIpNetTable, [MarshalAs(UnmanagedType.U4)] ref int pdwSize, bool bOrder);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate bool DelegateUnlockFile(IntPtr hFile, uint dwFileOffsetLow,
           uint dwFileOffsetHigh, uint nNumberOfBytesToUnlockLow,
           uint nNumberOfBytesToUnlockHigh);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateNetSessionEnum(
            [In, MarshalAs(UnmanagedType.LPWStr)]
            string serverName,
            [In, MarshalAs(UnmanagedType.LPWStr)]
            string uncClientName,
            [In, MarshalAs(UnmanagedType.LPWStr)]
            string userName,
            int level,
            out IntPtr pBuffer,
            int prefmaxlength,
            ref int entriesRead,
            ref int totalEntries,
            ref int resume_Handle);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateGetUdpStatistics(ref MIB_UDPSTATS pStats);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateGetUdpTable(byte[] UcpTable, out int pdwSize, bool bOrder);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateGetTcpStatistics(ref MIB_TCPSTATS pStats);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateGetTcpTable(byte[] pTcpTable, out int pdwSize, bool bOrder);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate IntPtr DelegateGetProcessHeap();

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateFormatMessage(int flags, IntPtr source, int messageId,
            int languageId, StringBuilder buffer, int size, IntPtr arguments);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateGetExtendedTcpTable(byte[] pTcpTable, out int dwOutBufLen, bool sort,
            int ipVersion, TCP_TABLE_CLASS tblClass, int reserved);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateGetExtendedUdpTable(byte[] pUdpTable, out int dwOutBufLen, bool sort,
            int ipVersion, UDP_TABLE_CLASS tblClass, int reserved);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate SafeFindHandle DelegateFindFirstStreamW(string lpFileName, StreamInfoLevels InfoLevel,
        [In, Out, MarshalAs(UnmanagedType.LPStruct)] 
        WIN32_FIND_STREAM_DATA lpFindStreamData, uint dwFlags);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate bool DelegateFindNextStreamW(SafeFindHandle hndFindFile,
        [In, Out, MarshalAs(UnmanagedType.LPStruct)] 
        WIN32_FIND_STREAM_DATA lpFindStreamData);


    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate IntPtr DelegateFindFirstFile(string lpFileName, out
        WIN32_FIND_DATA lpFindFileData);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate bool DelegateFindNextFile(IntPtr hFindFile, out
        WIN32_FIND_DATA lpFindFileData);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate bool DelegateFindClose(IntPtr hFindFile);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate IntPtr DelegateOpenEventLog(
        [MarshalAs(UnmanagedType.LPWStr)] string Server,
        [MarshalAs(UnmanagedType.LPWStr)] string Log);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate bool DelegateReadEventLog(
        IntPtr hLog,
        int ReadFlags,
        int RecordOffset,
        [Out, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPStruct)] byte[] records,
        int BytesToRead,
        out int BytesRead,
        out int MinBytesNeeded);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate bool DelegateConvertSidToStringSid(
        [MarshalAs(UnmanagedType.LPArray)] byte[] pSid,
        out IntPtr ptrSid);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate bool DelegateLookupAccountName(
        string systemName,
        string accountName,
        [MarshalAs(UnmanagedType.LPArray)]
        byte[] sid,
        ref uint cbSid,
        System.Text.StringBuilder referencedDomainName,
        ref uint cchReferencedDomainName,
        out SID_NAME_USE peUse);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateNetUserGetInfo(
            [MarshalAs(UnmanagedType.LPWStr)] string ServerName,
            [MarshalAs(UnmanagedType.LPWStr)] string UserName,
            int level,
            out IntPtr BufPtr);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateNetUserEnum(
            [MarshalAs(UnmanagedType.LPWStr)] string ServerName,
            int level,
            int filter,
            out IntPtr pBuffer,
            int prefMaxLen,
            out int entriesRead,
            out int totalEntries,
            out int resumeHandle);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateNetApiBufferFree(IntPtr Buffer);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateDsGetDcName(
            [MarshalAs(UnmanagedType.LPTStr)] string ComputerName,
            [MarshalAs(UnmanagedType.LPTStr)] string DomainName,
            [In] GuidClass DomainGuid,
            [MarshalAs(UnmanagedType.LPTStr)] string SiteName,
            DSGETDCNAME_FLAGS Flags,
            out IntPtr pDOMAIN_CONTROLLER_INFO
        );
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateNetLocalGroupGetMembers(
            [MarshalAs(UnmanagedType.LPWStr)] string servername,
            [MarshalAs(UnmanagedType.LPWStr)] string localgroupname,
            int level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref int resume_handle);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateNetLocalGroupEnum([MarshalAs(UnmanagedType.LPWStr)] 
            string servername,
            int level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref int resume_handle);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateRegOpenKeyEx(
            UIntPtr hKey,
            string subKey,
            int ulOptions,
            int samDesired,
            out UIntPtr hkResult);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateRegQueryValueEx(
        UIntPtr hKey,
        string lpValueName,
        IntPtr lpReserved,
        out RegKeyTypes lpType,
        [MarshalAs(UnmanagedType.LPArray), Out]
        byte[] data,
        ref uint lpcbData);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateRegQueryValueExString(
        UIntPtr hKey,
        string lpValueName,
        IntPtr lpReserved,
        out RegKeyTypes lpType,
        [MarshalAs(UnmanagedType.VBByRefStr)]
        ref string data,
        ref uint lpcbData);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateRegCloseKey(
        UIntPtr hKey);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateRegQueryInfoKey(
        UIntPtr hkey,
        out uint lpClass,
        ref uint lpcbClass,
        IntPtr lpReserved,
        out uint lpcSubKeys,
        out uint lpcbMaxSubKeyLen,
        out uint lpcbMaxClassLen,
        out uint lpcValues,
        out uint lpcbMaxValueNameLen,
        out uint lpcbMaxValueLen,
        out uint lpcbSecurityDescriptor,
        IntPtr lpftLastWriteTime);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate uint DelegateRegEnumValue(
            UIntPtr hKey,
            uint dwIndex,
            [MarshalAs(UnmanagedType.LPArray)]
            byte[] lpValueName,
            ref uint lpcValueName,
            IntPtr lpReserved,
            IntPtr lpType,
            IntPtr lpData,
            IntPtr lpcbData);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate uint DelegateRegEnumKeyEx(UIntPtr hkey,
        uint index,
        [MarshalAs(UnmanagedType.LPArray)]
        byte[] lpName,
        ref uint lpcbName,
        IntPtr reserved,
        IntPtr lpClass,
        IntPtr lpcbClass,
        out long lpftLastWriteTime);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate uint DelegateRegQueryReflectionKey(UIntPtr hBase, ref int disabled);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateNtOpenProcess(out IntPtr hProcess, UInt32 access, UIntPtr pObjectAttrib, uint pClient);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateNtQueryInformationProcess(IntPtr processHandle, PROCESSINFOCLASS pic, [MarshalAs(UnmanagedType.LPArray), Out] byte[] processInformation, int cb, out int pSize);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate void DelegateGetSystemInfo(out SYSTEM_INFO si);

    //[DllImport("psapi.dll", SetLastError = true)]
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate bool DelegateEnumProcesses(
        [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4), In, Out]
        UInt32[] pids,
        [MarshalAs(UnmanagedType.U4)] out UInt32 bytesCopied);
    /// <summary>
    /// Close handle to given object
    /// </summary>
    /// <param name="hObject">Handle to object</param>
    /// <returns>Non-zero if successful</returns>
    //[DllImport("kernel32.dll", SetLastError = true)]
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate bool DelegateCloseHandle(IntPtr hHandle);

    //[DllImport("kernel32.dll",SetLastError=true)]
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate IntPtr DelegateOpenProcess(UInt32 access, bool bInheritHandle, uint dwProcessId); //Change desired access back to uint if necessary



    //[DllImport("shell32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateDllGetVersion(ref DLLVERSIONINFO ddlVerInfo);

    //[DllImport("version.dll")]
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate bool DelegateGetFileVersionInfo(string sFileName,
             int handle, int size, byte[] infoBuffer);
    //[DllImport("version.dll")]
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateGetFileVersionInfoSize(string sFileName,
             out int handle);

    // The third parameter - "out string pValue" - is automatically 
    // marshaled from ANSI to Unicode: 
    //[DllImport("version.dll")]
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate bool DelegateVerQueryValue(byte[] pBlock,
             string pSubBlock, out IntPtr pValue, out uint len);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate Int32 DelegateReadProcessMemory(
            IntPtr hProcess,
            UIntPtr lpBaseAddress,
            [In, Out] byte[] buffer,
            UInt32 size,
            out UIntPtr lpNumberOfBytesRead
            );
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate Int32 DelegateReadProcessMemory64(
            IntPtr hProcess,
            UInt64 lpBaseAddress,
            [In, Out] byte[] buffer,
            UInt32 size,
            out UIntPtr lpNumberOfBytesRead
            );
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate bool DelegateOpenProcessToken(UIntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate bool DelegateAdjustTokenPrivileges(IntPtr TokenHandle,
        [MarshalAs(UnmanagedType.Bool)]bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        UInt32 Zero,
        UIntPtr Null1,
        UIntPtr Null2);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate bool DelegateLookupPrivilegeValue(string lpSystemName, string lpName,
        out LUID lpLuid);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate uint DelegateVirtualQueryEx(
        IntPtr hProcess,
        UIntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer,
        uint dwLength);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate uint DelegateVirtualQueryEx64(
        IntPtr hProcess,
        UIntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION64 lpBuffer,
        uint dwLength);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate UIntPtr DelegateGetCurrentProcess();

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate bool DelegateGetProcessTimes(IntPtr hProcess,
        [MarshalAs(UnmanagedType.Struct)] 
        out FILETIME creationTime,
        [MarshalAs(UnmanagedType.Struct)] 
        out FILETIME exitTime,
        [MarshalAs(UnmanagedType.Struct)] 
        out FILETIME kernelTime,
        [MarshalAs(UnmanagedType.Struct)] 
        out FILETIME userTime);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateProcess32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateProcess32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate IntPtr DelegateCreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateGetCurrentProcessId();

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateModule32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int DelegateModule32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate IntPtr DelegateCreateFile(string fileName,
        [MarshalAs(UnmanagedType.U4)] FileAccess fileAccess,
        [MarshalAs(UnmanagedType.U4)] FileShare fileShare,
        IntPtr securityAttributes,
        [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition,
        int flags,
        IntPtr template);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate bool DelegateCopyFile(string oldFileName, string newFileName, bool failIfExists);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate bool DelegateCreateDirectory(string pathName, IntPtr securityAttributes);
    #endregion
    //WinAPI Enums
    #region Enums
    public enum MSIINSTALLCONTEXT
    {
        //  Query that is extended to all per–user-managed installations for the users that szUserSid specifies. 
        UserManaged = 1,

        //  Query that is extended to all per–user-unmanaged installations for the users that szUserSid specifies.
        UserUnmanaged = 2,

        //  Query that is extended to all per-machine installations.
        Machine = 4
    }
    public enum NERR
    {
        SUCCESS = 0,
        ERR_MORE_DATA = 234,
        ERR_NO_BROWSER_SERVERS_FOUND = 6118,
        ERR_INVALID_LEVEL = 124,
        ERR_ACCESS_DENIED = 5,
        ERR_INVALID_PARAMETER = 87,
        ERR_NOT_ENOUGH_MEMORY = 8,
        ERR_NETWORK_BUSY = 54,
        ERR_BAD_NET_PATH = 53,
        ERR_NO_NETWORK = 1222,
        ERR_INVALID_HANDLE_STATE = 1609,
        ERR_EXTENDED_ERR = 1208,
        ERR_BASE = 2100,
        ERR_UNKNOWN_DIR = ERR_BASE + 16,
        ERR_DUPLICATE_SHARE = ERR_BASE + 18,
        ERR_BUFFER_TO_SMALL = ERR_BASE + 23
    }
    public enum TCPCONNSTATES
    {
        CLOSED = 1,
        LISTEN = 2,
        SYN_SENT = 3,
        SYN_RECV = 4,
        ESTABLISHED = 5,
        FIN_WAIT = 6,
        FIN_WAIT_HOLD = 7,
        CLOSE_WAIT = 8,
        CLOSING = 9,
        LAST_ACK = 10,
        TIME_WAIT = 11,
        DELETE_TCB = 12
    }
    [Flags]
    public enum UserFlags : int
    {
        GUEST_SESSION,
        NO_PASSWORD_ENCRYPTION
    }
    public enum CLTYPE : int
    {
        DOS_LM_1,
        DOS_LM_2,
        OS2_LM_1,
        OS2_LM_2
    }
    public enum StreamInfoLevels { FindStreamInfoStandard = 0 }

    [Flags]
    public enum EFileAccess : uint
    {
        GenericRead = 0x80000000,
        GenericWrite = 0x40000000,
        GenericExecute = 0x20000000,
        GenericAll = 0x10000000,
    }

    [Flags]
    public enum EFileShare : uint
    {
        None = 0x00000000,
        Read = 0x00000001,
        Write = 0x00000002,
        Delete = 0x00000004,
    }

    public enum ECreationDisposition : uint
    {
        New = 1,
        CreateAlways = 2,
        OpenExisting = 3,
        OpenAlways = 4,
        TruncateExisting = 5,
    }


    [Flags]
    public enum EFileAttributes : uint
    {
        Readonly = 0x00000001,
        Hidden = 0x00000002,
        System = 0x00000004,
        Directory = 0x00000010,
        Archive = 0x00000020,
        Device = 0x00000040,
        Normal = 0x00000080,
        Temporary = 0x00000100,
        SparseFile = 0x00000200,
        ReparsePoint = 0x00000400,
        Compressed = 0x00000800,
        Offline = 0x00001000,
        NotContentIndexed = 0x00002000,
        Encrypted = 0x00004000,
        Write_Through = 0x80000000,
        Overlapped = 0x40000000,
        NoBuffering = 0x20000000,
        RandomAccess = 0x10000000,
        SequentialScan = 0x08000000,
        DeleteOnClose = 0x04000000,
        BackupSemantics = 0x02000000,
        PosixSemantics = 0x01000000,
        OpenReparsePoint = 0x00200000,
        OpenNoRecall = 0x00100000,
        FirstPipeInstance = 0x00080000
    }
    public enum EventType : short
    {
        EVENT_ERROR_TYPE = 0x0001,
        EVENT_AUDIT_FAILURE = 0x0010,
        EVENT_AUDIT_SUCCESS = 0x0008,
        EVENT_INFORMATION_TYPE = 0x0004,
        EVENT_WARNING_TYPE = 0x0002
    }
    [Flags]
    public enum DSGETDCNAME_FLAGS : uint
    {
        DS_FORCE_REDISCOVERY = 0x00000001,
        DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010,
        DS_DIRECTORY_SERVICE_PREFERRED = 0x00000020,
        DS_GC_SERVER_REQUIRED = 0x00000040,
        DS_PDC_REQUIRED = 0x00000080,
        DS_BACKGROUND_ONLY = 0x00000100,
        DS_IP_REQUIRED = 0x00000200,
        DS_KDC_REQUIRED = 0x00000400,
        DS_TIMESERV_REQUIRED = 0x00000800,
        DS_WRITABLE_REQUIRED = 0x00001000,
        DS_GOOD_TIMESERV_PREFERRED = 0x00002000,
        DS_AVOID_SELF = 0x00004000,
        DS_ONLY_LDAP_NEEDED = 0x00008000,
        DS_IS_FLAT_NAME = 0x00010000,
        DS_IS_DNS_NAME = 0x00020000,
        DS_RETURN_DNS_NAME = 0x40000000,
        DS_RETURN_FLAT_NAME = 0x80000000
    }
    public enum RegKeyTypes
    {
        REG_NONE = 0,
        REG_SZ = 1,
        REG_EXPAND_SZ = 2,
        REG_BINARY = 3,
        REG_DWORD = 4,
        REG_DWORD_LITTLE_ENDIAN = 4,
        REG_DWORD_BIG_ENDIAN = 5,
        REG_LINK = 6,
        REG_MULTI_SZ = 7
    }
    public enum SID_NAME_USE
    {
        SidTypeUser = 1,
        SidTypeGroup,
        SidTypeDomain,
        SidTypeAlias,
        SidTypeWellKnownGroup,
        SidTypeDeletedAccount,
        SidTypeInvalid,
        SidTypeUnknown,
        SidTypeComputer
    }
    public enum PROCESSINFOCLASS : int
    {

        ProcessBasicInformation = 0,
        ProcessQuotaLimits,
        ProcessIoCounters,
        ProcessVmCounters,
        ProcessTimes,
        ProcessBasePriority,
        ProcessRaisePriority,
        ProcessDebugPort,
        ProcessExceptionPort,
        ProcessAccessToken,
        ProcessLdtInformation,
        ProcessLdtSize,
        ProcessDefaultHardErrorMode,
        ProcessIoPortHandlers, // Note: this is kernel mode only
        ProcessPooledUsageAndLimits,
        ProcessWorkingSetWatch,
        ProcessUserModeIOPL,
        ProcessEnableAlignmentFaultFixup,
        ProcessPriorityClass,
        ProcessWx86Information,
        ProcessHandleCount,
        ProcessAffinityMask,
        ProcessPriorityBoost,
        MaxProcessInfoClass,
        ProcessWow64Information,
        ProcessImageFileName = 27
    };
    public enum Privileges : int
    {
        GUEST = 0,
        USER = 1,
        ADMINISTRATOR = 2
    }
    public enum dwFlag : uint
    {
        TH32CS_INHERIT = 0x80000000,
        //TH32CS_SNAPALL = TH32CS_SNAPHEAPLIST | TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32 | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD,
        TH32CS_SNAPHEAPLIST = 0x00000001,
        TH32CS_SNAPMODULE = 0x00000008,
        TH32CS_SNAPMODULE32 = 0x00000010,
        TH32CS_SNAPPROCESS = 0x00000002,
        TH32CS_SNAPTHREAD = 0x00000004
    }
    public enum dwFilterFlag : int
    {
        LIST_MODULES_32BIT = 0X01,
        LIST_MODULES_64BIT = 0X02,
        LIST_MODULES_ALL = 0X03,
        LIST_MODULES_DEFAULT = 0X00
    }

    public enum dwDesiredAccess : uint
    {
        PROCESS_ALL_ACCESS = PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
        PROCESS_CREATE_PROCESS = 0x0080,
        PROCESS_CREATE_THREAD = 0x0002,
        PROCESS_DUP_HANDLE = 0x0040,
        PROCESS_QUERY_INFORMATION = 0x0400,
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
        PROCESS_SET_INFORMATION = 0x0200,
        PROCESS_SET_QUOTA = 0x0100,
        PROCESS_SUSPEND_RESUME = 0x0800,
        PROCESS_TERMINATE = 0x0001,
        PROCESS_VM_OPERATION = 0x0008,
        PROCESS_VM_READ = 0x0010,
        PROCESS_VM_WRITE = 0x0020
    }
    public enum ServiceType
    {
        SERVICE_KERNEL_DRIVER = 0x1,
        SERVICE_FILE_SYSTEM_DRIVER = 0x2,
        SERVICE_WIN32_OWN_PROCESS = 0x10,
        SERVICE_WIN32_SHARE_PROCESS = 0x20,
        SERVICE_INTERACTIVE_PROCESS = 0x100,
        SERVICE_NO_CHANGE = 0xffff,
        SERVICETYPE_NO_CHANGE = SERVICE_NO_CHANGE,
        SERVICE_WIN32 = (SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS)
    }

    public enum ServiceStateRequest
    {
        SERVICE_ACTIVE = 0x1,
        SERVICE_INACTIVE = 0x2,
        SERVICE_STATE_ALL = (SERVICE_ACTIVE | SERVICE_INACTIVE)
    }

    public enum ServiceControlManagerType
    {
        SC_MANAGER_CONNECT = 0x1,
        SC_MANAGER_CREATE_SERVICE = 0x2,
        SC_MANAGER_ENUMERATE_SERVICE = 0x4,
        SC_MANAGER_LOCK = 0x8,
        SC_MANAGER_QUERY_LOCK_STATUS = 0x10,
        SC_MANAGER_MODIFY_BOOT_CONFIG = 0x20,
        STANDARD_RIGHTS_REQUIRED = 0xf000,
        SC_MANAGER_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED |
            SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE |
            SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_LOCK |
            SC_MANAGER_QUERY_LOCK_STATUS | SC_MANAGER_MODIFY_BOOT_CONFIG
    }
    public enum OS
    {
        XP = 1,
        Vista = 2,
        Seven = 3
    }
    public enum Which
    {
        Registry = 1,
        Net = 2,
        Process = 3,
        Scan = 4,
        Error = 5,
        Events = 6,
        AV = 7,
        Info = 8
    }
    public enum DrivesToCheck
    {
        LocalDrives,
        AllDrives,
        CDRom,
        OsDrive
    }
    #endregion
    //WinAPI Structs
    #region structs
    public struct UserAndSidType
    {
        public string DomainAndUser;
        public SID_NAME_USE sidUse;
    }
    public struct ProductPatchInfo
    {
        public string Date;
        public string Name;
    }
    public struct TcpConnectionRow
    {
        public string strState;
        public IPAddress ipLocalAddr;
        public IPAddress ipRemoteAddr;
        public int ipLocalPort;
        public int ipRemotePort;
        public int PID;
    }
    public struct UdpConnectionRow
    {
        public IPAddress ipLocalAddr;
        public int ipLocalPort;
        public int PID;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct SESSION_INFO_502
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string cname;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string userName;
        public int open;
        public int time;
        public int idle;
        public UserFlags flags;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string clType;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string transport;
    }
    #region UDP

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDPROW_OWNER_PID
    {
        public IPEndPoint Local;
        public int dwOwningPid;
        public string ProcessName;
    }

    public struct MIB_UDPROW_OWNER_MODULE
    {
        public IPEndPoint Local;
        public uint dwOwningPid;
        public long liCreateTimestamp; //LARGE_INTEGER
        /*union {
            struct {
                DWORD   SpecificPortBind : 1;
            };
            DWORD       dwFlags;
        };*/
        public ulong[] OwningModuleInfo; //size TCPIP_OWNING_MODULE_SIZE
    }

    public struct MIB_UDPTABLE_OWNER_PID
    {
        public int dwNumEntries;
        public MIB_UDPROW_OWNER_PID[] table;
    }

    public struct _MIB_UDPTABLE_OWNER_MODULE
    {
        public uint dwNumEntries;
        public MIB_UDPROW_OWNER_MODULE[] table;
    }

    public enum UDP_TABLE_CLASS
    {
        UDP_TABLE_BASIC, //A MIB_UDPTABLE table that contains all UDP endpoints on the machine is returned to the caller.
        UDP_TABLE_OWNER_PID, //A MIB_UDPTABLE_OWNER_PID or MIB_UDP6TABLE_OWNER_PID that contains all UDP endpoints on the machine is returned to the caller.
        UDP_TABLE_OWNER_MODULE //A MIB_UDPTABLE_OWNER_MODULE or MIB_UDP6TABLE_OWNER_MODULE that contains all UDP endpoints on the machine is returned to the caller.
    }

    public struct MIB_UDPSTATS
    {
        public int dwInDatagrams;
        public int dwNoPorts;
        public int dwInErrors;
        public int dwOutDatagrams;
        public int dwNumAddrs;
    }

    public struct MIB_UDPTABLE
    {
        public int dwNumEntries;
        public MIB_UDPROW[] table;
    }

    public struct MIB_UDPROW
    {
        public IPEndPoint Local;
    }

    public struct MIB_EXUDPTABLE
    {
        public int dwNumEntries;
        public MIB_EXUDPROW[] table;

    }

    public struct MIB_EXUDPROW
    {
        public IPEndPoint Local;
        public int dwProcessId;
        public string ProcessName;
    }

    #endregion

    #region TCP
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPTABLE_OWNER_MODULE
    {
        public uint dwNumEntries;
        public MIB_TCPROW_OWNER_MODULE[] table;
    }

    public struct MIB_TCPROW_OWNER_MODULE
    {
        public const int TCPIP_OWNING_MODULE_SIZE = 16;
        public uint dwState;
        public IPEndPoint Local; //LocalAddress
        public IPEndPoint Remote; //RemoteAddress
        public uint dwOwningPid;
        public uint liCreateTimestamp; //LARGE_INTEGER
        public ulong[] OwningModuleInfo; //Look how to define array size in structure ULONGLONG   = new ulong[TCPIP_OWNING_MODULE_SIZE]     
    }

    public struct MIB_TCPTABLE_OWNER_PID
    {
        public int dwNumEntries;
        public MIB_TCPROW_OWNER_PID[] table;
    }

    public struct MIB_TCPROW_OWNER_PID
    {
        public int dwState;
        public IPEndPoint Local; //LocalAddress
        public IPEndPoint Remote; //RemoteAddress
        public int dwOwningPid;
        public string State;
        public string ProcessName;
    }

    public enum TCP_TABLE_CLASS
    {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL,
        TCP_TABLE_OWNER_MODULE_LISTENER,
        TCP_TABLE_OWNER_MODULE_CONNECTIONS,
        TCP_TABLE_OWNER_MODULE_ALL,
    }

    public struct MIB_TCPSTATS
    {
        public int dwRtoAlgorithm;
        public int dwRtoMin;
        public int dwRtoMax;
        public int dwMaxConn;
        public int dwActiveOpens;
        public int dwPassiveOpens;
        public int dwAttemptFails;
        public int dwEstabResets;
        public int dwCurrEstab;
        public int dwInSegs;
        public int dwOutSegs;
        public int dwRetransSegs;
        public int dwInErrs;
        public int dwOutRsts;
        public int dwNumConns;
    }

    public struct MIB_TCPTABLE
    {
        public int dwNumEntries;
        public MIB_TCPROW[] table;
    }

    public struct MIB_TCPROW
    {
        public string StrgState;
        public int iState;
        public IPEndPoint Local;
        public IPEndPoint Remote;
    }

    public struct MIB_EXTCPTABLE
    {
        public int dwNumEntries;
        public MIB_EXTCPROW[] table;

    }

    public struct MIB_EXTCPROW
    {
        public string StrgState;
        public int iState;
        public IPEndPoint Local;
        public IPEndPoint Remote;
        public int dwProcessId;
        public string ProcessName;
    }
    #endregion
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_IPNETROW
    {
        [MarshalAs(UnmanagedType.U4)]
        public int dwIndex;
        [MarshalAs(UnmanagedType.U4)]
        public int dwPhysAddrLen;
        [MarshalAs(UnmanagedType.U1)]
        public byte mac0;
        [MarshalAs(UnmanagedType.U1)]
        public byte mac1;
        [MarshalAs(UnmanagedType.U1)]
        public byte mac2;
        [MarshalAs(UnmanagedType.U1)]
        public byte mac3;
        [MarshalAs(UnmanagedType.U1)]
        public byte mac4;
        [MarshalAs(UnmanagedType.U1)]
        public byte mac5;
        [MarshalAs(UnmanagedType.U1)]
        public byte mac6;
        [MarshalAs(UnmanagedType.U1)]
        public byte mac7;
        [MarshalAs(UnmanagedType.U4)]
        public int dwAddr;
        [MarshalAs(UnmanagedType.U4)]
        public int dwType;
    }
    public struct FileInformation
    {
        public string strFilePath;
        public string strMD5;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public class WIN32_FIND_STREAM_DATA
    {
        //change back to a long instead of uint if this breaks
        public long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
        public string cStreamName;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WIN32_FIND_DATA
    {
        public FileAttributes dwFileAttributes;
        public FILETIME ftCreationTime;
        public FILETIME ftLastAccessTime;
        public FILETIME ftLastWriteTime;
        public int nFileSizeHigh;
        public int nFileSizeLow;
        public int dwReserved0;
        public int dwReserved1;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string cFileName;
        // not using this
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
        public string cAlternate;
    }



    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct EVENTLOGRECORD
    {
        public int Length;
        public int Reserved;
        public int RecordNumber;
        public DateTime TimeGenerated;
        public DateTime TimeWritten;
        public int EventID;
        public EventType EventType;
        public Int16 NumStrings;
        public Int16 EventCategory;
        public Int16 ReservedFlags;
        public int ClosingRecordNumber;
        public int StringOffset;
        public int UserSidOffset;
        public int UserSidLength;
        public int DataLength;
        public int DataOffset;
        public string sourceName;
        public string computerName;
        public string[] arrMessageStrings;
        public override string ToString()
        {
            string formatBasic = string.Format("{0,-10}{1,-5}{2,-30}{3,-5}{4,-30}{5,-5}{6,-10}{7,-5}{8,-20}{9,-5}{10,-10}{11,-5}{12,-30}{13,-5}{14,-30}{15,-5}",
                RecordNumber, "", "\t" + TimeGenerated, "", "\t" + TimeWritten, "", "\t" + EventID, "", "\t" + EventType, "", "\t" + EventCategory, "",
                "\t" + sourceName, "", "\t" + computerName, "");
            for (int i = 0; i < arrMessageStrings.Length; i++)
            {
                formatBasic += string.Format("{0},{1,10}", arrMessageStrings[i], "");
            }
            return formatBasic;
        }
        public string ToStringWithoutMessageStrings()
        {
            string formatBasic = string.Format("{0,-10}{1,-5}{2,-30}{3,-5}{4,-30}{5,-5}{6,-10}{7,-5}{8,-20}{9,-5}{10,-10}{11,-5}{12,-30}{13,-5}{14,-30}{15,-5}",
                RecordNumber, "", "\t" + TimeGenerated, "", "\t" + TimeWritten, "", "\t" + EventID, "", "\t" + EventType, "", "\t" + EventCategory, "",
                "\t" + sourceName, "", "\t" + computerName, "");
            return formatBasic;
        }
    }

    [StructLayoutAttribute(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct LOCALGROUP_MEMBERS_INFO_1
    {
        public IntPtr lgrmi1_sid;
        public IntPtr lgrmi1_sidusage;
        public IntPtr lgrmi1_name;

    }

    [StructLayoutAttribute(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct LOCALGROUP_INFO_1
    {
        public IntPtr lpszGroupName;
        public IntPtr lpszComment;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct LOCALGROUP_USERS_INFO_0
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string name;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LOCALGROUP_USERS_INFO_1
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string name;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string comment;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct LOCALGROUP_MEMBERS_INFO_2
    {
        public IntPtr lgrmi2_sid;
        public int lgrmi2_sidusage;
        public IntPtr lgrmi2_domainandname;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct DOMAIN_CONTROLLER_INFO
    {
        [MarshalAs(UnmanagedType.LPTStr)]
        public string DomainControllerName;
        [MarshalAs(UnmanagedType.LPTStr)]
        public string DomainControllerAddress;
        public uint DomainControllerAddressType;
        public Guid DomainGuid;
        [MarshalAs(UnmanagedType.LPTStr)]
        public string DomainName;
        [MarshalAs(UnmanagedType.LPTStr)]
        public string DnsForestName;
        public uint Flags;
        [MarshalAs(UnmanagedType.LPTStr)]
        public string DcSiteName;
        [MarshalAs(UnmanagedType.LPTStr)]
        public string ClientSiteName;
    }
    [StructLayout(LayoutKind.Sequential)]
    public class GuidClass
    {
        public Guid TheGuid;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct USER_INFO_10
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string usri10_name;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string usri10_comment;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string usri10_usr_comment;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string usri10_full_name;
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public UInt32 Attributes;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct ENUM_SERVICE_STATUS_PROCESS
    {
        public static readonly int SizePack4 = Marshal.SizeOf(typeof(ENUM_SERVICE_STATUS_PROCESS));

        /// <summary>
        /// sizeof(ENUM_SERVICE_STATUS_PROCESS) allow Packing of 8 on 64 bit machines
        /// </summary>
        public static readonly int SizePack8 = Marshal.SizeOf(typeof(ENUM_SERVICE_STATUS_PROCESS)) + 4;

        [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
        public string pServiceName;

        [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
        public string pDisplayName;

        public SERVICE_STATUS_PROCESS ServiceStatus;
    }
    public struct FILETIME
    {
        public uint dwLowDateTime;
        public uint dwHighDateTime;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_INFO
    {
        internal _PROCESSOR_INFO_UNION uProcessorInfo;
        public uint dwPageSize;
        public UIntPtr lpMinimumApplicationAddress;
        public UIntPtr lpMaximumApplicationAddress;
        public UIntPtr dwActiveProcessorMask;
        public uint dwNumberOfProcessors;
        public uint dwProcessorType;
        public uint dwAllocationGranularity;
        public ushort dwProcessorLevel;
        public ushort dwProcessorRevision;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct _PROCESSOR_INFO_UNION
    {
        [FieldOffset(0)]
        internal uint dwOemId;
        [FieldOffset(0)]
        internal ushort wProcessorArchitecture;
        [FieldOffset(2)]
        internal ushort wReserved;
    }
    public struct MEMORY_BASIC_INFORMATION
    {
        public UIntPtr BaseAddress;
        public UIntPtr AllocationBase;
        public int AllocationProtect;
        public int RegionSize;
        public int State;
        public int Protect;
        public int Type;
    }
    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct MEMORY_BASIC_INFORMATION64
    {
        public UInt64 BaseAddress;
        public UInt64 AllocationBase;
        public int AllocationProtect;
        public int __alignment1;
        public UInt64 RegionSize;
        public int State;
        public int Protect;
        public int Type;
        public int __alignment2;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct VS_FIXEDFILEINFO
    {
        public int dwSignature;
        public int dwStrucVersion;
        public int dwFileVersionMS;
        public int dwFileVersionLS;
        public int dwProductVersionMS;
        public int dwProductVersionLS;
        public int dwFileFlagsMask;
        public int dwFileFlags;
        public int dwFileOS;
        public int dwFileType;
        public int dwFileSubType;
        public int dwFileDateMS;
        public int dwFileDateLS;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct DLLVERSIONINFO
    {
        public int dwSize;
        public int dwMajorVersion;
        public int dwMinorVersion;
        public int dwBuild;
        public int dwPlatformID;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public UIntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    public struct MODULEENTRY32
    {
        public uint dwSize;
        public uint th32ModuleID;
        public uint th32ProcessID;
        public uint GlblcntUsage;
        public uint ProccntUsage;
        public UIntPtr modBaseAddr;
        public uint modBaseSize;
        public UIntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct PROCESS_BASIC_INFORMATION
    {
        public int ExitStatus;
        public int PebBaseAddress;
        public int AffinityMask;
        public int BasePriority;
        public int UniqueProcessId;
        public int InheritedFromUniqueProcessId;

        public int Size
        {
            get { return (6 * 4); }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public UInt32 PrivilegeCount;
        public LUID Luid;
        public UInt32 Attributes;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public UInt32 LowPart;
        public Int32 HighPart;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct LANGUAGECODEPAGE
    {
        public short Lang;
        public short Code;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct SERVICE_STATUS_PROCESS
    {
        public int serviceType;
        public int currentState;
        public int controlsAccepted;
        public int win32ExitCode;
        public int serviceSpecificExitCode;
        public int checkPoint;
        public int waitHint;
        public int processId;
        public int serviceFlags;
    }


    public struct USER_INFO_1
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string usri1_name;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string usri1_password;
        public int passwordAge;
        public Privileges privs;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string usri1_home_dir;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string usri1_usr_comment;
        int flags;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string usri1_script_path;
    }
    public struct USER_NAMES
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string name;
    }
    public struct Sender
    {
        public string Message;
        public Which which;
    }
    #endregion
    public class Functions
    {
        Functions()
        {
            //Retrieve all WinApi Function Pointers
            InitializeWinAPI();
        }
        #region delegatefunctionality
        #region delegates
        public static DelegateGetTickCount64 pFuncGetTickCount64;
        public static DelegateGetTickCount pFuncGetTickCount;
        public static DelegateMsiGetPatchInfoEx pFuncMsiGetPatchInfoEx;
        public static DelegateMsiEnumPatchesEx pFuncMsiEnumPatchesEx;
        public static DelegateEnumServicesStatusEx pFuncEnumServicesStatusEx;
        public static DelegateOpenSCManager pFuncOpenSCManager;
        public static DelegateCloseServiceHandle pFuncCloseServiceHandle;

        public static DelegateReadFile pFuncReadFile;
        public static DelegateGetIpNetTable pFuncGetIpNetTable;
        public static DelegateUnlockFile pFuncUnlockFile;
        public static DelegateNetSessionEnum pFuncNetSessionEnum;
        public static DelegateGetUdpStatistics pFuncGetUdpStatistics;
        public static DelegateGetUdpTable pFuncGetUdpTable;
        public static DelegateGetTcpStatistics pFuncGetTcpStatistics;
        public static DelegateGetTcpTable pFuncGetTcpTable;
        public static DelegateGetProcessHeap pFuncGetProcessHeap;
        public static DelegateFormatMessage pFuncFormatMessage;
        public static DelegateGetExtendedTcpTable pFuncGetExtendedTcpTable;
        public static DelegateGetExtendedUdpTable pFuncGetExtendedUdpTable;

        public static DelegateFindFirstStreamW pFuncFindFirstStreamW;
        public static DelegateFindNextStreamW pFuncFindNextStreamW;
        public static DelegateFindClose pFuncFindClose;
        public static DelegateFindFirstFile pFuncFindFirstFile;
        public static DelegateFindNextFile pFuncFindNextFile;

        public static DelegateOpenEventLog pFuncOpenEventLog;
        public static DelegateReadEventLog pFuncReadEventLog;

        public static DelegateConvertSidToStringSid pFuncConvertSidToStringSid;
        public static DelegateLookupAccountName pFuncLookupAccountName;

        public static DelegateNetUserEnum pFuncNetUserEnum;
        public static DelegateNetApiBufferFree pFuncNetApiBufferFree;
        public static DelegateDsGetDcName pFuncDsGetDcName;
        public static DelegateNetLocalGroupGetMembers pFuncNetLocalGroupGetMembers;
        public static DelegateNetLocalGroupEnum pFuncNetLocalGroupEnum;
        public static DelegateNetUserGetInfo pFuncNetUserGetInfo;

        public static DelegateRegOpenKeyEx pFuncRegOpenKeyEx;
        public static DelegateRegQueryValueEx pFuncRegQueryValueExA;
        public static DelegateRegQueryReflectionKey pFuncRegQueryReflectionKey;
        public static DelegateRegCloseKey pFuncRegCloseKey;
        public static DelegateRegQueryInfoKey pFuncRegQueryInfoKeyA;
        public static DelegateRegEnumValue pFuncRegEnumValueA;
        public static DelegateRegEnumKeyEx pFuncRegEnumKeyExA;
        public static DelegateRegQueryValueEx pFuncRegQueryValueExW;
        public static DelegateRegQueryInfoKey pFuncRegQueryInfoKeyW;
        public static DelegateRegEnumValue pFuncRegEnumValueW;
        public static DelegateRegEnumKeyEx pFuncRegEnumKeyExW;


        public static DelegateNtQueryInformationProcess pFuncNtQueryProcInfo;
        public static DelegateNtOpenProcess pFuncNtOpenProcess;
        public static DelegateReadProcessMemory pFuncReadProcessMemory;
        public static DelegateVirtualQueryEx pFuncVirtualQueryEx;
        public static DelegateVirtualQueryEx64 pFuncVirtualQueryEx64;
        public static DelegateGetCurrentProcess pFuncGetCurrentProcess;
        public static DelegateGetProcessTimes pFuncGetProcessTimes;
        public static DelegateProcess32First pFunc;
        public static DelegateProcess32First pFuncProcess32First;
        public static DelegateProcess32Next pFuncProcess32Next;
        public static DelegateCreateToolhelp32Snapshot pFuncCreateToolhelp32Snapshot;
        public static DelegateGetCurrentProcessId pFuncGetCurrentProcessId;
        public static DelegateModule32First pFuncModule32First;
        public static DelegateModule32Next pFuncModule32Next;
        public static DelegateGetSystemInfo pFuncGetSystemInfo;
        public static DelegateCreateFile pFuncCreateFile;
        public static DelegateCreateDirectory pFuncCreateDirectory;
        public static DelegateCopyFile pFuncCopyFile;
        public static DelegateOpenProcessToken pFuncOpenProcessToken;
        public static DelegateAdjustTokenPrivileges pFuncAdjustTokenPrivileges;
        public static DelegateLookupPrivilegeValue pFuncLookupPrivilegeValue;
        public static DelegateDllGetVersion pFuncDllGetVersion;
        public static DelegateGetFileVersionInfo pFuncGetFileVersionInfo;
        public static DelegateGetFileVersionInfoSize pFuncGetFileVersionInfoSize;
        public static DelegateVerQueryValue pFuncVerQueryValue;
        public static DelegateEnumProcesses pFuncEnumProcesses;
        public static DelegateCloseHandle pFuncCloseHandle;
        public static DelegateOpenProcess pFuncOpenProcess;
        public static DelegateReadProcessMemory64 pFuncReadProcessMemory64;

        #endregion
        #region funcStrings
        static string ntDll = @"C:\Windows\System32\ntdll.dll";
        static string kernel = @"C:\Windows\System32\kernel32.dll";
        static string psApi = @"C:\Windows\System32\psapi.dll";
        static string version = @"C:\Windows\System32\version.dll";
        static string advapi32 = @"C:\Windows\System32\advapi32.dll";
        static string wininet = @"C:\Windows\System32\wininet.dll";
        static string iphlpapi = @"C:\Windows\System32\iphlpapi.dll";
        static string msi = @"C:\Windows\System32\Msi.dll";
        static string shell32 = @"shell32.dll";
        static string netapi32 = @"NetAPI32.dll";

        static string strGetTickCount64 = @"GetTickCount64";
        static string strGetTickCount = @"GetTickCount";
        static string strMsiGetPatchInfoEx = @"MsiGetPatchInfoExA";
        static string strMsiEnumPatchesEx = @"MsiEnumPatchesExA";
        static string strEnumServicesStatusEx = @"EnumServicesStatusExW";
        static string strOpenSCManager = @"OpenSCManagerW";
        static string strCloseServiceHandle = @"CloseServiceHandle";

        static string strReadFile = @"ReadFile";
        static string strGetIpNetTable = @"GetIpNetTable";
        static string strUnlockFile = @"UnlockFile";
        static string strNetSessionEnum = @"NetSessionEnum";
        static string strGetUdpStatistics = @"GetUdpStatistics";
        static string strGetUdpTable = @"GetUdpTable";
        static string strGetTcpStatistics = @"GetTcpStatistics";
        static string strGetTcpTable = @"GetTcpTable";
        static string strGetProcessHeap = @"GetProcessHeap";
        static string strFormatMessage = @"FormatMessageA";
        static string strGetExtendedTcpTable = @"GetExtendedTcpTable";
        static string strGetExtendedUdpTable = @"GetExtendedUdpTable";

        static string strFuncFindFirstStream = @"FindFirstStreamW";
        static string strFuncFindNextStream = @"FindNextStreamW";
        static string strFuncFindClose = @"FindClose";
        static string strFuncFindFirstFile = @"FindFirstFileW";
        static string strFuncFindNextFile = @"FindNextFileW";

        static string strFuncOpenEventLog = @"OpenEventLogA";
        static string strFuncReadEventLog = @"ReadEventLogA";

        static string strFuncConvertSidToStringSid = @"ConvertSidToStringSidA";
        static string strFuncLookupAccountName = @"LookupAccountNameA";

        static string strFuncNetUserEnum = @"NetUserEnum";
        static string strFuncNetApiBufferFree = @"NetApiBufferFree";
        static string strFuncDsGetDcName = @"DsGetDcNameW";
        static string strFuncNetLocalGroupGetMembers = @"NetLocalGroupGetMembers";
        static string strFuncNetLocalGroupEnum = @"NetLocalGroupEnum";
        static string strFuncNetUserGetInfo = @"NetUserGetInfo";

        static string strFuncRegQueryValueExA = @"RegQueryValueExA";
        static string strFuncRegOpenKeyEx = @"RegOpenKeyExA";
        static string strFuncRegQueryValueExW = @"RegQueryValueExW";
        static string strFuncRegCloseKey = @"RegCloseKey";
        static string strFuncRegQueryInfoKeyA = @"RegQueryInfoKeyA";
        static string strFuncRegQueryInfoKeyW = @"RegQueryInfoKeyW";
        static string strFuncRegEnumValueA = @"RegEnumValueA";
        static string strFuncRegEnumValueW = @"RegEnumValueW";
        static string strFuncRegEnumKeyExW = @"RegEnumKeyExW";
        static string strFuncRegEnumKeyExA = @"RegEnumKeyExA";
        static string strFuncRegQueryReflectionKey = @"RegQueryReflectionKey";

        static string strFuncNtOpenProcess = @"NtOpenProcess";
        static string strFuncReadProcessMemory = @"ReadProcessMemory";
        static string strFuncReadProcessMemory64 = @"ReadProcessMemory";
        static string strFuncVirtualQueryEx = @"VirtualQueryEx";
        static string strFuncVirtualQueryEx64 = @"VirtualQueryEx";
        static string strFuncGetCurrentProcess = @"GetCurrentProcess";
        static string strFuncGetSystemInfo = @"GetSystemInfo";
        static string strFuncGetProcessTimes = @"GetProcessTimes";
        static string strFuncProcess32First = @"Process32First";
        static string strFuncProcess32Next = @"Process32Next";
        static string strFuncCreateToolhelp32Snapshot = @"CreateToolhelp32Snapshot";
        static string strFuncGetCurrentProcessId = @"GetCurrentProcessId";
        static string strFuncModule32First = @"Module32First";
        static string strFuncModule32Next = @"Module32Next";
        static string strFuncCreateFile = @"CreateFileA";
        static string strFuncCreateDirectory = @"CreateDirectoryA";
        static string strFuncCopyFile = @"CopyFileA";
        static string strFuncOpenProcessToken = @"OpenProcessToken";
        static string strFuncAdjustTokenPrivileges = @"AdjustTokenPrivileges";
        static string strFuncLookupPrivilegeValue = @"LookupPrivilegeValueA";
        static string strFuncDllGetVersion = @"DllGetVersion";
        static string strFuncGetFileVersionInfo = @"GetFileVersionInfoA";
        static string strFuncGetFileVersionInfoSize = @"GetFileVersionInfoSizeA";
        static string strFuncVerQueryValue = @"VerQueryValueA";
        static string strFuncEnumProcesses = @"EnumProcesses";
        static string strFuncCloseHandle = @"CloseHandle";
        static string strFuncOpenProcess = @"OpenProcess";
        #endregion
        #endregion
        //Import all WinAPI Functions
        static void InitializeWinAPI()
        {
            IntPtr hLibNtDll = LoadLibrary(ntDll);
            IntPtr hLibKernel = LoadLibrary(kernel);
            IntPtr hLibWininet = LoadLibrary(wininet);
            IntPtr hLibPsapi = LoadLibrary(psApi);
            IntPtr hLibAdvapi = LoadLibrary(advapi32);
            IntPtr hLibVersion = LoadLibrary(version);
            IntPtr hLibIphlpapi = LoadLibrary(iphlpapi);
            IntPtr hLibMsi = LoadLibrary(msi);
            IntPtr hLibShell = LoadLibrary(shell32);
            IntPtr hLibNetApi = LoadLibrary(netapi32);

            #region funcPointers
            /*
            static string strGetTickCount64  = @"pFuncGetTickCount64";
            static string strGetTickCount  = @"pFuncGetTickCount";
            static string strMsiGetPatchInfoEx  = @"pFuncMsiGetPatchInfoEx";
            static string strMsiEnumPatchesEx  = @"pFuncMsiEnumPatchesEx";
            static string strEnumServicesStatusEx  = @"pFuncEnumServicesStatusEx";
            static string strOpenSCManager  = @"pFuncOpenSCManager";
            static string strCloseServiceHandle = @"pFuncCloseServiceHandle";
            */
            try
            {
                IntPtr hFuncGetTickCount64 = GetProcAddress(hLibKernel, strGetTickCount64);
                pFuncGetTickCount64 = (DelegateGetTickCount64)Marshal.GetDelegateForFunctionPointer(hFuncGetTickCount64, typeof(DelegateGetTickCount64));
            }
            catch (ArgumentNullException ex)
            {

            }
            IntPtr hFuncGetTickCount = GetProcAddress(hLibKernel, strGetTickCount);
            pFuncGetTickCount = (DelegateGetTickCount)Marshal.GetDelegateForFunctionPointer(hFuncGetTickCount, typeof(DelegateGetTickCount));

            IntPtr hFuncMsiGetPatchInfoEx = GetProcAddress(hLibMsi, strMsiGetPatchInfoEx);
            pFuncMsiGetPatchInfoEx = (DelegateMsiGetPatchInfoEx)Marshal.GetDelegateForFunctionPointer(hFuncMsiGetPatchInfoEx, typeof(DelegateMsiGetPatchInfoEx));

            IntPtr hFuncMsiEnumPatchesEx = GetProcAddress(hLibMsi, strMsiEnumPatchesEx);
            pFuncMsiEnumPatchesEx = (DelegateMsiEnumPatchesEx)Marshal.GetDelegateForFunctionPointer(hFuncMsiEnumPatchesEx, typeof(DelegateMsiEnumPatchesEx));

            IntPtr hFuncEnumServicesStatusEx = GetProcAddress(hLibAdvapi, strEnumServicesStatusEx);
            pFuncEnumServicesStatusEx = (DelegateEnumServicesStatusEx)Marshal.GetDelegateForFunctionPointer(hFuncEnumServicesStatusEx, typeof(DelegateEnumServicesStatusEx));

            IntPtr hFuncOpenSCManager = GetProcAddress(hLibAdvapi, strOpenSCManager);
            pFuncOpenSCManager = (DelegateOpenSCManager)Marshal.GetDelegateForFunctionPointer(hFuncOpenSCManager, typeof(DelegateOpenSCManager));

            IntPtr hFuncCloseServiceHandle = GetProcAddress(hLibAdvapi, strCloseServiceHandle);
            pFuncCloseServiceHandle = (DelegateCloseServiceHandle)Marshal.GetDelegateForFunctionPointer(hFuncCloseServiceHandle, typeof(DelegateCloseServiceHandle));

            IntPtr hFuncReadFile = GetProcAddress(hLibKernel, strReadFile);
            pFuncReadFile = (DelegateReadFile)Marshal.GetDelegateForFunctionPointer(hFuncReadFile, typeof(DelegateReadFile));

            IntPtr hFuncGetIpNetTable = GetProcAddress(hLibIphlpapi, strGetIpNetTable);
            pFuncGetIpNetTable = (DelegateGetIpNetTable)Marshal.GetDelegateForFunctionPointer(hFuncGetIpNetTable, typeof(DelegateGetIpNetTable));

            IntPtr hFuncUnlockFile = GetProcAddress(hLibKernel, strUnlockFile);
            pFuncUnlockFile = (DelegateUnlockFile)Marshal.GetDelegateForFunctionPointer(hFuncUnlockFile, typeof(DelegateUnlockFile));

            IntPtr hFuncNetSessionEnum = GetProcAddress(hLibNetApi, strNetSessionEnum);
            pFuncNetSessionEnum = (DelegateNetSessionEnum)Marshal.GetDelegateForFunctionPointer(hFuncNetSessionEnum, typeof(DelegateNetSessionEnum));

            IntPtr hFuncGetUdpStatistics = GetProcAddress(hLibIphlpapi, strGetUdpStatistics);
            pFuncGetUdpStatistics = (DelegateGetUdpStatistics)Marshal.GetDelegateForFunctionPointer(hFuncGetUdpStatistics, typeof(DelegateGetUdpStatistics));

            IntPtr hFuncGetUdpTable = GetProcAddress(hLibIphlpapi, strGetUdpTable);
            pFuncGetUdpTable = (DelegateGetUdpTable)Marshal.GetDelegateForFunctionPointer(hFuncGetUdpTable, typeof(DelegateGetUdpTable));

            IntPtr hFuncGetTcpStatistics = GetProcAddress(hLibIphlpapi, strGetTcpStatistics);
            pFuncGetTcpStatistics = (DelegateGetTcpStatistics)Marshal.GetDelegateForFunctionPointer(hFuncGetTcpStatistics, typeof(DelegateGetTcpStatistics));

            IntPtr hFuncGetTcpTable = GetProcAddress(hLibIphlpapi, strGetTcpTable);
            pFuncGetTcpTable = (DelegateGetTcpTable)Marshal.GetDelegateForFunctionPointer(hFuncGetTcpTable, typeof(DelegateGetTcpTable));

            IntPtr hFuncGetProcessHeap = GetProcAddress(hLibKernel, strGetProcessHeap);
            pFuncGetProcessHeap = (DelegateGetProcessHeap)Marshal.GetDelegateForFunctionPointer(hFuncGetProcessHeap, typeof(DelegateGetProcessHeap));

            IntPtr hFuncFormatMessage = GetProcAddress(hLibKernel, strFormatMessage);
            pFuncFormatMessage = (DelegateFormatMessage)Marshal.GetDelegateForFunctionPointer(hFuncFormatMessage, typeof(DelegateFormatMessage));

            IntPtr hFuncGetExtendedTcpTable = GetProcAddress(hLibIphlpapi, strGetExtendedTcpTable);
            pFuncGetExtendedTcpTable = (DelegateGetExtendedTcpTable)Marshal.GetDelegateForFunctionPointer(hFuncGetExtendedTcpTable, typeof(DelegateGetExtendedTcpTable));

            IntPtr hFuncGetExtendedUdpTable = GetProcAddress(hLibIphlpapi, strGetExtendedUdpTable);
            pFuncGetExtendedUdpTable = (DelegateGetExtendedUdpTable)Marshal.GetDelegateForFunctionPointer(hFuncGetExtendedUdpTable, typeof(DelegateGetExtendedUdpTable));
            try
            {
                IntPtr hFuncFindFirstStreamW = GetProcAddress(hLibKernel, strFuncFindFirstStream);
                pFuncFindFirstStreamW = (DelegateFindFirstStreamW)Marshal.GetDelegateForFunctionPointer(hFuncFindFirstStreamW, typeof(DelegateFindFirstStreamW));

                IntPtr hFuncFindNextStreamW = GetProcAddress(hLibKernel, strFuncFindNextStream);
                pFuncFindNextStreamW = (DelegateFindNextStreamW)Marshal.GetDelegateForFunctionPointer(hFuncFindNextStreamW, typeof(DelegateFindNextStreamW));
            }
            catch (ArgumentNullException ex)
            {

            }
            IntPtr hFuncFindClose = GetProcAddress(hLibKernel, strFuncFindClose);
            pFuncFindClose = (DelegateFindClose)Marshal.GetDelegateForFunctionPointer(hFuncFindClose, typeof(DelegateFindClose));

            IntPtr hFuncFindFirstFile = GetProcAddress(hLibKernel, strFuncFindFirstFile);
            pFuncFindFirstFile = (DelegateFindFirstFile)Marshal.GetDelegateForFunctionPointer(hFuncFindFirstFile, typeof(DelegateFindFirstFile));

            IntPtr hFuncFindNextFile = GetProcAddress(hLibKernel, strFuncFindNextFile);
            pFuncFindNextFile = (DelegateFindNextFile)Marshal.GetDelegateForFunctionPointer(hFuncFindNextFile, typeof(DelegateFindNextFile));

            IntPtr hFuncReadEventLog = GetProcAddress(hLibAdvapi, strFuncReadEventLog);
            pFuncReadEventLog = (DelegateReadEventLog)Marshal.GetDelegateForFunctionPointer(hFuncReadEventLog, typeof(DelegateReadEventLog));

            IntPtr hFuncOpenEventLog = GetProcAddress(hLibAdvapi, strFuncOpenEventLog);
            pFuncOpenEventLog = (DelegateOpenEventLog)Marshal.GetDelegateForFunctionPointer(hFuncOpenEventLog, typeof(DelegateOpenEventLog));

            IntPtr hFuncConvertSidToStringSid = GetProcAddress(hLibAdvapi, strFuncConvertSidToStringSid);
            pFuncConvertSidToStringSid = (DelegateConvertSidToStringSid)Marshal.GetDelegateForFunctionPointer(hFuncConvertSidToStringSid, typeof(DelegateConvertSidToStringSid));

            IntPtr hFuncLookupAccountName = GetProcAddress(hLibAdvapi, strFuncLookupAccountName);
            pFuncLookupAccountName = (DelegateLookupAccountName)Marshal.GetDelegateForFunctionPointer(hFuncLookupAccountName, typeof(DelegateLookupAccountName));

            IntPtr hFuncRegOpenKeyEx = GetProcAddress(hLibAdvapi, strFuncRegOpenKeyEx);
            pFuncRegOpenKeyEx = (DelegateRegOpenKeyEx)Marshal.GetDelegateForFunctionPointer(hFuncRegOpenKeyEx, typeof(DelegateRegOpenKeyEx));

            IntPtr hFuncNetUserGetInfo = GetProcAddress(hLibNetApi, strFuncNetUserGetInfo);
            pFuncNetUserGetInfo = (DelegateNetUserGetInfo)Marshal.GetDelegateForFunctionPointer(hFuncNetUserGetInfo, typeof(DelegateNetUserGetInfo));

            IntPtr hFuncRegQueryValueExA = GetProcAddress(hLibAdvapi, strFuncRegQueryValueExA);
            pFuncRegQueryValueExA = (DelegateRegQueryValueEx)Marshal.GetDelegateForFunctionPointer(hFuncRegQueryValueExA, typeof(DelegateRegQueryValueEx));

            IntPtr hFuncRegQueryReflectionKey = GetProcAddress(hLibAdvapi, strFuncRegQueryReflectionKey);
            pFuncRegQueryReflectionKey = (DelegateRegQueryReflectionKey)Marshal.GetDelegateForFunctionPointer(hFuncRegQueryValueExA, typeof(DelegateRegQueryReflectionKey));

            IntPtr hFuncRegQueryValueExW = GetProcAddress(hLibAdvapi, strFuncRegQueryValueExW);
            pFuncRegQueryValueExW = (DelegateRegQueryValueEx)Marshal.GetDelegateForFunctionPointer(hFuncRegQueryValueExW, typeof(DelegateRegQueryValueEx));

            IntPtr hFuncRegCloseKey = GetProcAddress(hLibAdvapi, strFuncRegCloseKey);
            pFuncRegCloseKey = (DelegateRegCloseKey)Marshal.GetDelegateForFunctionPointer(hFuncRegCloseKey, typeof(DelegateRegCloseKey));

            IntPtr hFuncRegQueryInfoKeyA = GetProcAddress(hLibAdvapi, strFuncRegQueryInfoKeyA);
            pFuncRegQueryInfoKeyA = (DelegateRegQueryInfoKey)Marshal.GetDelegateForFunctionPointer(hFuncRegQueryInfoKeyA, typeof(DelegateRegQueryInfoKey));

            IntPtr hFuncNetUserEnum = GetProcAddress(hLibNetApi, strFuncNetUserEnum);
            pFuncNetUserEnum = (DelegateNetUserEnum)Marshal.GetDelegateForFunctionPointer(hFuncNetUserEnum, typeof(DelegateNetUserEnum));

            IntPtr hFuncNetApiBufferFree = GetProcAddress(hLibNetApi, strFuncNetApiBufferFree);
            pFuncNetApiBufferFree = (DelegateNetApiBufferFree)Marshal.GetDelegateForFunctionPointer(hFuncNetApiBufferFree, typeof(DelegateNetApiBufferFree));

            IntPtr hFuncDsGetDcName = GetProcAddress(hLibNetApi, strFuncDsGetDcName);
            pFuncDsGetDcName = (DelegateDsGetDcName)Marshal.GetDelegateForFunctionPointer(hFuncDsGetDcName, typeof(DelegateDsGetDcName));

            IntPtr hFuncNetLocalGroupGetMembers = GetProcAddress(hLibNetApi, strFuncNetLocalGroupGetMembers);
            pFuncNetLocalGroupGetMembers = (DelegateNetLocalGroupGetMembers)Marshal.GetDelegateForFunctionPointer(hFuncNetLocalGroupGetMembers, typeof(DelegateNetLocalGroupGetMembers));

            IntPtr hFuncNetLocalGroupEnum = GetProcAddress(hLibNetApi, strFuncNetLocalGroupEnum);
            pFuncNetLocalGroupEnum = (DelegateNetLocalGroupEnum)Marshal.GetDelegateForFunctionPointer(hFuncNetLocalGroupEnum, typeof(DelegateNetLocalGroupEnum));

            IntPtr hFuncRegQueryInfoKeyW = GetProcAddress(hLibAdvapi, strFuncRegQueryInfoKeyW);
            pFuncRegQueryInfoKeyW = (DelegateRegQueryInfoKey)Marshal.GetDelegateForFunctionPointer(hFuncRegQueryInfoKeyW, typeof(DelegateRegQueryInfoKey));

            IntPtr hFuncRegEnumValueA = GetProcAddress(hLibAdvapi, strFuncRegEnumValueA);
            pFuncRegEnumValueA = (DelegateRegEnumValue)Marshal.GetDelegateForFunctionPointer(hFuncRegEnumValueA, typeof(DelegateRegEnumValue));

            IntPtr hFuncRegEnumKeyExW = GetProcAddress(hLibAdvapi, strFuncRegEnumKeyExW);
            pFuncRegEnumKeyExW = (DelegateRegEnumKeyEx)Marshal.GetDelegateForFunctionPointer(hFuncRegEnumKeyExW, typeof(DelegateRegEnumKeyEx));

            IntPtr hFuncRegEnumValueW = GetProcAddress(hLibAdvapi, strFuncRegEnumValueW);
            pFuncRegEnumValueW = (DelegateRegEnumValue)Marshal.GetDelegateForFunctionPointer(hFuncRegEnumValueW, typeof(DelegateRegEnumValue));

            IntPtr hFuncRegEnumKeyExA = GetProcAddress(hLibAdvapi, strFuncRegEnumKeyExA);
            pFuncRegEnumKeyExA = (DelegateRegEnumKeyEx)Marshal.GetDelegateForFunctionPointer(hFuncRegEnumKeyExA, typeof(DelegateRegEnumKeyEx));

            IntPtr hFuncNtQueryProcess = GetProcAddress(hLibNtDll, "NtQueryInformationProcess");
            pFuncNtQueryProcInfo = (DelegateNtQueryInformationProcess)Marshal.GetDelegateForFunctionPointer(hFuncNtQueryProcess, typeof(DelegateNtQueryInformationProcess));

            IntPtr hFuncNtOpenProcess = GetProcAddress(hLibNtDll, strFuncNtOpenProcess);
            pFuncNtOpenProcess = (DelegateNtOpenProcess)Marshal.GetDelegateForFunctionPointer(hFuncNtOpenProcess, typeof(DelegateNtOpenProcess));

            IntPtr hFuncGetSystemInfo = GetProcAddress(hLibKernel, strFuncGetSystemInfo);
            pFuncGetSystemInfo = (DelegateGetSystemInfo)Marshal.GetDelegateForFunctionPointer(hFuncGetSystemInfo, typeof(DelegateGetSystemInfo));

            IntPtr hFuncEnumProcesses = GetProcAddress(hLibPsapi, strFuncEnumProcesses);
            pFuncEnumProcesses = (DelegateEnumProcesses)Marshal.GetDelegateForFunctionPointer(hFuncEnumProcesses, typeof(DelegateEnumProcesses));

            IntPtr hFuncCloseHandle = GetProcAddress(hLibKernel, strFuncCloseHandle);
            pFuncCloseHandle = (DelegateCloseHandle)Marshal.GetDelegateForFunctionPointer(hFuncCloseHandle, typeof(DelegateCloseHandle));

            IntPtr hFuncOpenProcess = GetProcAddress(hLibKernel, strFuncOpenProcess);
            pFuncOpenProcess = (DelegateOpenProcess)Marshal.GetDelegateForFunctionPointer(hFuncOpenProcess, typeof(DelegateOpenProcess));

            IntPtr hFuncOpenProcessToken = GetProcAddress(hLibAdvapi, strFuncOpenProcessToken);
            pFuncOpenProcessToken = (DelegateOpenProcessToken)Marshal.GetDelegateForFunctionPointer(hFuncOpenProcessToken, typeof(DelegateOpenProcessToken));

            IntPtr hFuncDllGetVersion = GetProcAddress(hLibShell, strFuncDllGetVersion);
            pFuncDllGetVersion = (DelegateDllGetVersion)Marshal.GetDelegateForFunctionPointer(hFuncDllGetVersion, typeof(DelegateDllGetVersion));

            IntPtr hFuncGetFileVersionInfo = GetProcAddress(hLibVersion, strFuncGetFileVersionInfo);
            pFuncGetFileVersionInfo = (DelegateGetFileVersionInfo)Marshal.GetDelegateForFunctionPointer(hFuncGetFileVersionInfo, typeof(DelegateGetFileVersionInfo));

            IntPtr hFuncGetFileVersionInfoSize = GetProcAddress(hLibVersion, strFuncGetFileVersionInfoSize);
            pFuncGetFileVersionInfoSize = (DelegateGetFileVersionInfoSize)Marshal.GetDelegateForFunctionPointer(hFuncGetFileVersionInfoSize, typeof(DelegateGetFileVersionInfoSize));

            IntPtr hFuncVerQueryValue = GetProcAddress(hLibVersion, strFuncVerQueryValue);
            pFuncVerQueryValue = (DelegateVerQueryValue)Marshal.GetDelegateForFunctionPointer(hFuncVerQueryValue, typeof(DelegateVerQueryValue));

            IntPtr hFuncAdjustTokenPrivileges = GetProcAddress(hLibAdvapi, strFuncAdjustTokenPrivileges);
            pFuncAdjustTokenPrivileges = (DelegateAdjustTokenPrivileges)Marshal.GetDelegateForFunctionPointer(hFuncAdjustTokenPrivileges, typeof(DelegateAdjustTokenPrivileges));

            IntPtr hFuncLookupPrivilegeValue = GetProcAddress(hLibAdvapi, strFuncLookupPrivilegeValue);
            pFuncLookupPrivilegeValue = (DelegateLookupPrivilegeValue)Marshal.GetDelegateForFunctionPointer(hFuncLookupPrivilegeValue, typeof(DelegateLookupPrivilegeValue));

            IntPtr hFuncReadProcessMemory64 = GetProcAddress(hLibKernel, strFuncReadProcessMemory64);
            pFuncReadProcessMemory64 = (DelegateReadProcessMemory64)Marshal.GetDelegateForFunctionPointer(hFuncReadProcessMemory64, typeof(DelegateReadProcessMemory64));

            IntPtr hFuncReadProcessMemory = GetProcAddress(hLibKernel, strFuncReadProcessMemory);
            pFuncReadProcessMemory = (DelegateReadProcessMemory)Marshal.GetDelegateForFunctionPointer(hFuncReadProcessMemory, typeof(DelegateReadProcessMemory));

            IntPtr hFuncVirtualQueryEx = GetProcAddress(hLibKernel, strFuncVirtualQueryEx);
            pFuncVirtualQueryEx = (DelegateVirtualQueryEx)Marshal.GetDelegateForFunctionPointer(hFuncVirtualQueryEx, typeof(DelegateVirtualQueryEx));

            IntPtr hFuncVirtualQueryEx64 = GetProcAddress(hLibKernel, strFuncVirtualQueryEx64);
            pFuncVirtualQueryEx64 = (DelegateVirtualQueryEx64)Marshal.GetDelegateForFunctionPointer(hFuncVirtualQueryEx64, typeof(DelegateVirtualQueryEx64));

            IntPtr hFuncGetCurrentProcess = GetProcAddress(hLibKernel, strFuncGetCurrentProcess);
            pFuncGetCurrentProcess = (DelegateGetCurrentProcess)Marshal.GetDelegateForFunctionPointer(hFuncGetCurrentProcess, typeof(DelegateGetCurrentProcess));

            IntPtr hFuncGetProcessTimes = GetProcAddress(hLibKernel, strFuncGetProcessTimes);
            pFuncGetProcessTimes = (DelegateGetProcessTimes)Marshal.GetDelegateForFunctionPointer(hFuncGetProcessTimes, typeof(DelegateGetProcessTimes));

            IntPtr hFuncProcess32First = GetProcAddress(hLibKernel, strFuncProcess32First);
            pFuncProcess32First = (DelegateProcess32First)Marshal.GetDelegateForFunctionPointer(hFuncProcess32First, typeof(DelegateProcess32First));

            IntPtr hFuncProcess32Next = GetProcAddress(hLibKernel, strFuncProcess32Next);
            pFuncProcess32Next = (DelegateProcess32Next)Marshal.GetDelegateForFunctionPointer(hFuncProcess32Next, typeof(DelegateProcess32Next));

            IntPtr hFuncCreateToolhelp32Snapshot = GetProcAddress(hLibKernel, strFuncCreateToolhelp32Snapshot);
            pFuncCreateToolhelp32Snapshot = (DelegateCreateToolhelp32Snapshot)Marshal.GetDelegateForFunctionPointer(hFuncCreateToolhelp32Snapshot, typeof(DelegateCreateToolhelp32Snapshot));

            IntPtr hFuncGetCurrentProcessId = GetProcAddress(hLibKernel, strFuncGetCurrentProcessId);
            pFuncGetCurrentProcessId = (DelegateGetCurrentProcessId)Marshal.GetDelegateForFunctionPointer(hFuncGetCurrentProcessId, typeof(DelegateGetCurrentProcessId));

            IntPtr hFuncModule32First = GetProcAddress(hLibKernel, strFuncModule32First);
            pFuncModule32First = (DelegateModule32First)Marshal.GetDelegateForFunctionPointer(hFuncModule32First, typeof(DelegateModule32First));

            IntPtr hFuncModule32Next = GetProcAddress(hLibKernel, strFuncModule32Next);
            pFuncModule32Next = (DelegateModule32Next)Marshal.GetDelegateForFunctionPointer(hFuncModule32Next, typeof(DelegateModule32Next));

            IntPtr hFuncCreateFile = GetProcAddress(hLibKernel, strFuncCreateFile);
            pFuncCreateFile = (DelegateCreateFile)Marshal.GetDelegateForFunctionPointer(hFuncCreateFile, typeof(DelegateCreateFile));

            IntPtr hFuncCreateDirectory = GetProcAddress(hLibKernel, strFuncCreateDirectory);
            pFuncCreateDirectory = (DelegateCreateDirectory)Marshal.GetDelegateForFunctionPointer(hFuncCreateDirectory, typeof(DelegateCreateDirectory));

            IntPtr hFuncCopyFile = GetProcAddress(hLibKernel, strFuncCopyFile);
            pFuncCopyFile = (DelegateCopyFile)Marshal.GetDelegateForFunctionPointer(hFuncCopyFile, typeof(DelegateCopyFile));

            #endregion
        }
        //LoadLibrary cannot by referenced via internal pointer so it is being directly imported here
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadLibrary(string fileName);
        //GetProcAddress cannot by referenced via internal pointer so it is being directly imported here
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string funcName);

        #region Helper Functions
        /// <summary>
        /// Converts tick time to readable time
        /// </summary>
        /// <param name="time"></param>
        /// <returns></returns>
        public static string FileTimeToDateTime(FILETIME time)
        {
            long longTime = ((long)time.dwHighDateTime) << 32 | time.dwLowDateTime;
            DateTime dt = DateTime.FromFileTimeUtc(longTime);
            return dt.ToString();
        }
        #endregion

    }
    public sealed class SafeFindHandle : SafeHandleMinusOneIsInvalid
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public SafeFindHandle()
            : base(true)
        {
        }

        /// <summary>
        /// Release the find handle
        /// </summary>
        /// <returns>true if the handle was released</returns>
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        protected override bool ReleaseHandle()
        {
            return Functions.pFuncFindClose(handle);
        }
    }
}