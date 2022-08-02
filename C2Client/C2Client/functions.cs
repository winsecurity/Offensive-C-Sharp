using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.IO;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Collections;
using System.Collections.Specialized;
using System.Collections.Generic;
using System.Diagnostics;

namespace C2Client
{
    public partial class winapi
    {

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

        public enum LSA_AccessPolicy : long
        {
            POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
            POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
            POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
            POLICY_TRUST_ADMIN = 0x00000008L,
            POLICY_CREATE_ACCOUNT = 0x00000010L,
            POLICY_CREATE_SECRET = 0x00000020L,
            POLICY_CREATE_PRIVILEGE = 0x00000040L,
            POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
            POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
            POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
            POLICY_SERVER_ADMIN = 0x00000400L,
            POLICY_LOOKUP_NAMES = 0x00000800L,
            POLICY_NOTIFICATION = 0x00001000L
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_OBJECT_ATTRIBUTES
        {
            public UInt32 Length;
            public IntPtr RootDirectory;
            public LSA_UNICODE_STRING ObjectName;
            public UInt32 Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }



        [DllImport("Advapi32.dll")]
        public static extern int LsaOpenPolicy(
            ref string systemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            UInt64 DesiredAccess,
            ref IntPtr PolicyHandle
            );


        [DllImport("Advapi32.dll")]
        public static extern int LsaClose(
                IntPtr PolicyHandle
            );


        [DllImport("Advapi32.dll")]
        public static extern int LsaEnumerateAccountRights(
            IntPtr lsahandle,
           [param: MarshalAs(UnmanagedType.LPArray)] byte[] AccountSid,
            ref IntPtr UserRights,
            ref UInt64 CountOfRights
            );


        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int LookupAccountNameW(
            [param: MarshalAs(UnmanagedType.LPWStr)] string lpSystemName,
            [param: MarshalAs(UnmanagedType.LPWStr)] string lpAccountName,
            [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
            ref uint cbsize,
            StringBuilder ReferencedDomainName,
            ref uint cchReferencedDomainName,
            ref int peUse);




        [DllImport("Advapi32.dll")]
        public static extern int LsaAddAccountRights(
            IntPtr PolicyHandle,
            [param: MarshalAs(UnmanagedType.LPArray)] byte[] AccountSid,
            LSA_UNICODE_STRING UserRights,
            UInt64 CountOfRights
            );


        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_LAST_INTER_LOGON_INFO
        {
            public LARGE_INTEGER LastSuccessfulLogon;
            public LARGE_INTEGER LastFailedLogon;
            public ulong FailedAttemptCountSinceLastSuccessfulLogon;
        }

        [StructLayout(LayoutKind.Explicit, Size = 8)]
        public struct LARGE_INTEGER
        {
            [FieldOffset(0)] public Int64 QuadPart;
            [FieldOffset(0)] public UInt32 LowPart;
            [FieldOffset(4)] public Int32 HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public UInt32 LowPart;
            public UInt32 HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_LOGON_SESSION_DATA
        {
            public UInt32 Size;
            public LUID LoginID;
            public LSA_UNICODE_STRING UserName;
            public LSA_UNICODE_STRING LoginDomain;
            public LSA_UNICODE_STRING AuthenticationPackage;
            public UInt32 LogonType;
            public UInt32 Session;
            public IntPtr Sid;
            public UInt64 LoginTime;
            public LSA_UNICODE_STRING LogonServer;
            public LSA_UNICODE_STRING DnsDomainName;
            public LSA_UNICODE_STRING Upn;

        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }


        [DllImport("Secur32.dll")]
        public static extern int LsaEnumerateLogonSessions(
            ref UInt64 LogonSessionCount,
            ref IntPtr LogonSessionList
            );

        [DllImport("Secur32.dll")]
        public static extern int LsaFreeReturnBuffer(IntPtr t);

        [DllImport("Secur32.dll")]
        public static extern int LsaGetLogonSessionData(
            IntPtr LogonId,
            ref IntPtr ppLogonSessionData
            );



        [StructLayout(LayoutKind.Sequential)]
        public struct SHARE_INFO_0
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string shi0_netname;
        }


        [StructLayoutAttribute(LayoutKind.Sequential)]
        public struct SECURITY_DESCRIPTOR
        {
            public byte revision;
            public byte size;
            public short control;
            [MarshalAs(UnmanagedType.LPArray)] public byte[] owner;
            public IntPtr group;
            public IntPtr sacl;
            public IntPtr dacl;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SHARE_INFO_2
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string shi2_netname;
            public UInt32 shi2_type;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string shi2_remark;
            public UInt32 shi2_permissions;
            public UInt32 shi2_max_uses;
            public UInt32 shi2_current_uses;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string shi2_path;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string shi2_passwd;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SHARE_INFO_503
        {
            [MarshalAs(UnmanagedType.LPWStr)] public string shi503_netname;
            public UInt32 shi503_type;
            [MarshalAs(UnmanagedType.LPWStr)] public string shi503_remark;
            public UInt32 shi503_permissions;
            public UInt32 shi503_max_uses;
            public UInt32 shi503_current_uses;
            [MarshalAs(UnmanagedType.LPWStr)] public string shi503_path;
            [MarshalAs(UnmanagedType.LPWStr)] public string shi503_passwd;
            [MarshalAs(UnmanagedType.LPWStr)] public string shi503_servername;
            public UInt32 shi503_reserved;
            public IntPtr shi503_security_descriptor;
        }


        [DllImport("Advapi32.dll")]
        public static extern int ConvertSidToStringSidW(
            [param: MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
           ref IntPtr username
            );


        [DllImport("Netapi32.dll")]
        public static extern int NetShareEnum(
            [param: MarshalAs(UnmanagedType.LPWStr)] string servername,
            int level,
            ref IntPtr bufptr,
            UInt32 prefmaxlen,
            ref UInt32 entriesread,
            ref UInt32 totalentries,
            IntPtr resume_handle
            );


        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] e_magic;       // Magic number
            public UInt16 e_cblp;    // Bytes on last page of file
            public UInt16 e_cp;      // Pages in file
            public UInt16 e_crlc;    // Relocations
            public UInt16 e_cparhdr;     // Size of header in paragraphs
            public UInt16 e_minalloc;    // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;    // Maximum extra paragraphs needed
            public UInt16 e_ss;      // Initial (relative) SS value
            public UInt16 e_sp;      // Initial SP value
            public UInt16 e_csum;    // Checksum
            public UInt16 e_ip;      // Initial IP value
            public UInt16 e_cs;      // Initial (relative) CS value
            public UInt16 e_lfarlc;      // File address of relocation table
            public UInt16 e_ovno;    // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res1;    // Reserved words
            public UInt16 e_oemid;       // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;     // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2;    // Reserved words
            public Int32 e_lfanew;      // File address of new exe header
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }



        public enum MachineType : ushort
        {
            /// <summary>
            /// The content of this field is assumed to be applicable to any machine type
            /// </summary>
            Unknown = 0x0000,
            /// <summary>
            /// Intel 386 or later processors and compatible processors
            /// </summary>
            I386 = 0x014c,
            R3000 = 0x0162,
            /// <summary>
            ///  MIPS little endian
            /// </summary>
            R4000 = 0x0166,
            R10000 = 0x0168,
            /// <summary>
            /// MIPS little-endian WCE v2
            /// </summary>
            WCEMIPSV2 = 0x0169,
            /// <summary>
            /// Alpha AXP
            /// </summary>
            Alpha = 0x0184,
            /// <summary>
            /// Hitachi SH3
            /// </summary>
            SH3 = 0x01a2,
            /// <summary>
            /// Hitachi SH3 DSP
            /// </summary>
            SH3DSP = 0x01a3,
            /// <summary>
            /// Hitachi SH4
            /// </summary>
            SH4 = 0x01a6,
            /// <summary>
            /// Hitachi SH5
            /// </summary>
            SH5 = 0x01a8,
            /// <summary>
            /// ARM little endian
            /// </summary>
            ARM = 0x01c0,
            /// <summary>
            /// Thumb
            /// </summary>
            Thumb = 0x01c2,
            /// <summary>
            /// ARM Thumb-2 little endian
            /// </summary>
            ARMNT = 0x01c4,
            /// <summary>
            /// Matsushita AM33
            /// </summary>
            AM33 = 0x01d3,
            /// <summary>
            /// Power PC little endian
            /// </summary>
            PowerPC = 0x01f0,
            /// <summary>
            /// Power PC with floating point support
            /// </summary>
            PowerPCFP = 0x01f1,
            /// <summary>
            /// Intel Itanium processor family
            /// </summary>
            IA64 = 0x0200,
            /// <summary>
            /// MIPS16
            /// </summary>
            MIPS16 = 0x0266,
            /// <summary>
            /// Motorola 68000 series
            /// </summary>
            M68K = 0x0268,
            /// <summary>
            /// Alpha AXP 64-bit
            /// </summary>
            Alpha64 = 0x0284,
            /// <summary>
            /// MIPS with FPU
            /// </summary>
            MIPSFPU = 0x0366,
            /// <summary>
            /// MIPS16 with FPU
            /// </summary>
            MIPSFPU16 = 0x0466,
            /// <summary>
            /// EFI byte code
            /// </summary>
            EBC = 0x0ebc,
            /// <summary>
            /// RISC-V 32-bit address space
            /// </summary>
            RISCV32 = 0x5032,
            /// <summary>
            /// RISC-V 64-bit address space
            /// </summary>
            RISCV64 = 0x5064,
            /// <summary>
            /// RISC-V 128-bit address space
            /// </summary>
            RISCV128 = 0x5128,
            /// <summary>
            /// x64
            /// </summary>
            AMD64 = 0x8664,
            /// <summary>
            /// ARM64 little endian
            /// </summary>
            ARM64 = 0xaa64,
            /// <summary>
            /// LoongArch 32-bit processor family
            /// </summary>
            LoongArch32 = 0x6232,
            /// <summary>
            /// LoongArch 64-bit processor family
            /// </summary>
            LoongArch64 = 0x6264,
            /// <summary>
            /// Mitsubishi M32R little endian
            /// </summary>
            M32R = 0x9041
        }
        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }
        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14

        }
        public enum DllCharacteristicsType : ushort
        {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }


        [StructLayout(LayoutKind.Explicit)]
        public unsafe struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;
            [FieldOffset(8)] public UInt32 VirtualSize;
            [FieldOffset(12)] public UInt32 VirtualAddress;
            [FieldOffset(16)] public UInt32 SizeOfRawData;
            [FieldOffset(20)] public UInt32 PointerToRawData;
            [FieldOffset(24)] public UInt32 PointerToRelocations;
            [FieldOffset(28)] public UInt32 PointerToLinenumbers;
            [FieldOffset(32)] public UInt16 NumberOfRelocations;
            [FieldOffset(34)] public UInt16 NumberOfLinenumbers;
            [FieldOffset(36)] public UInt32 Characteristics;
            public string Section
            {

                get { return new string(Name); }
            }

        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            [FieldOffset(24)]
            public ulong ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public ulong SizeOfStackReserve;

            [FieldOffset(80)]
            public ulong SizeOfStackCommit;

            [FieldOffset(88)]
            public ulong SizeOfHeapReserve;

            [FieldOffset(96)]
            public ulong SizeOfHeapCommit;

            [FieldOffset(104)]
            public uint LoaderFlags;

            [FieldOffset(108)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(224)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(232)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }


        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_BASE_RELOCATION
        {
            [FieldOffset(0)]
            public UInt32 pagerva;

            [FieldOffset(4)]
            public UInt32 size;
        }


        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_NT_HEADERS64
        {
            [FieldOffset(0)]
            public UInt32 Signature;

            [FieldOffset(4)]
            public IMAGE_FILE_HEADER FileHeader;

            [FieldOffset(24)]
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;




        }


        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_IMPORT_DESCRIPTOR
        {
            [FieldOffset(0)]
            public uint Characteristics;

            [FieldOffset(0)]
            public uint OriginalFirstThunk;

            [FieldOffset(4)]
            public uint TimeDateStamp;

            [FieldOffset(8)]
            public uint ForwarderChain;

            [FieldOffset(12)]
            public uint Name;

            [FieldOffset(16)]
            public uint FirstThunk;
        }


        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_THUNK_DATA32
        {
            [FieldOffset(0)]
            public uint ForwarderString;

            [FieldOffset(0)]
            public uint Function;

            [FieldOffset(0)]
            public uint Ordinal;

            [FieldOffset(0)]
            public uint AddressOfData;
        }


        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_THUNK_DATA64
        {
            [FieldOffset(0)]
            public ulong ForwarderString;

            [FieldOffset(0)]
            public ulong Function;

            [FieldOffset(0)]
            public ulong Ordinal;

            [FieldOffset(0)]
            public ulong AddressOfData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_IMPORT_BY_NAME
        {

            public UInt16 Hint;
            public char Name;

        }


        [DllImport("Kernel32.dll")]
        public static extern int GetLastError();




        [DllImport("Kernel32.dll")]
        public static extern void CopyMemory(
            IntPtr destination,
            IntPtr source,
            int size
            );


        [DllImport("Kernel32.dll")]
        public static extern bool UnmapViewOfFile(IntPtr address);


        [DllImport("Kernel32.dll")]
        public static extern IntPtr MapViewOfFile(
            IntPtr hFileMappingObject,
            UInt32 dwDesiredAccess,
            UInt32 dwFileOffsetHigh,
            UInt32 dwFileOffsetLow,
            int dwNumberOfBytesToMap
            );


        [DllImport("Kernel32.dll")]
        public static extern IntPtr OpenFileMappingA(
            UInt32 dwDesiredAccess,
            [param: MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
            string lpName
            );

        [DllImport("Kernel32.dll")]
        public static extern IntPtr CreateFileMappingA(
            IntPtr filehandle,
            IntPtr lpFileMappingAttributes,
            UInt32 flProtect,
            UInt32 dwMaximumSizeHigh,
            UInt32 dwMaximumSizeLow,
            string lpName
            );


        [DllImport("Kernel32.dll")]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            int dwSize,
            UInt32 flAllocationType,
            UInt32 flProtect
            );


        [DllImport("Kernel32.dll")]
        public static extern bool VirtualFree(
            IntPtr lpAddress,
            int dwSize,
            UInt32 dwFreeType
            );

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);

        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetProcAddress(
            IntPtr handle,
            string functionname
            );

        [DllImport("Kernel32.dll")]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32", CharSet = CharSet.Ansi)]
        public static extern IntPtr CreateThread(
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            ref uint lpThreadId);


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
   UInt32 dwSize, uint flNewProtect, ref uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(
         IntPtr hProcess,
         IntPtr lpBaseAddress,
         byte[] lpBuffer,
         Int32 nSize,
         ref UInt32 lpNumberOfBytesWritten
        );


        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess,
   IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
   IntPtr lpParameter, uint dwCreationFlags, ref uint lpThreadId);


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }




        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }


        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool CreateProcessA(
            string applicationpath,
            string commandline,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool inherithandles,
            UInt32 dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION pinfo
            );


        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
   uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            UInt32 dwDesiredAccess,
            bool inherithandle,
            UInt32 dwProcessId
            );



        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(
            UInt32 desiredaccess,
            bool inherithandle,
            UInt32 threadid
            );


        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFreeEx(
            IntPtr prochandle,
            IntPtr baseaddress,
            UInt32 size,
            UInt32 freetype
            );


        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern UInt32 SleepEx(
            UInt32 dwMilliseconds,
            bool bAlertable
            );


        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern UInt32 QueueUserAPC(
            IntPtr functionaddress,
            IntPtr threadhandle,
            IntPtr functionparameter
            );


        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern UInt32 WaitForSingleObjectEx(
            IntPtr objecthandle,
            UInt32 milliseconds,
            bool alertable
            );

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern UInt32 ResumeThread(
           IntPtr threadhandle
           );



    }
}
