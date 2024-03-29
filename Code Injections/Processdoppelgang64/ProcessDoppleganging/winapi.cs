﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.IO;
using System.Diagnostics;

namespace ProcessDoppleganging
{
    public partial class Program
    {

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("KtmW32.dll", SetLastError = true)]
        public static extern IntPtr CreateTransaction(
            IntPtr lpTransactionAttributes,
            IntPtr UOW,
            UInt32 CreateOptions,
            UInt32 IsolationLevel,
            UInt32 IsolationFlags,
            UInt32 Timeout,
            [MarshalAs(UnmanagedType.LPWStr)] string Description
            );


        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateFileTransactedA(
           string filename,
            UInt32 dwDesiredAccess,
            UInt32 dwShareMode,
            IntPtr lpSecurityAttributes,
            UInt32 dwCreationDisposition,
            UInt32 dwFlagsAndAttributes,
            IntPtr hTemplateFile,
            IntPtr hTransaction,
            IntPtr pusMiniVersion,
            IntPtr lpExtendedParameter
            );


        [DllImport("KtmW32.dll")]
        public static extern bool CommitTransaction(IntPtr thandle);


        [DllImport("KtmW32.dll")]
        public static extern bool RollbackTransaction(IntPtr thandle);


        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool WriteFile(
            IntPtr filehandle,
            byte[] lpBuffer,
            UInt32 nNumberOfBytesToWrite,
            out uint lpNumberOfBytesWritten,
            IntPtr lpOverlapped
            );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer,
   uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);



        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        static extern UInt32 NtCreateSection(
            ref IntPtr SectionHandle,
            UInt32 DesiredAccess,
            IntPtr ObjectAttributes,
            ref UInt32 MaximumSize,
            UInt32 SectionPageProtection,
            UInt32 AllocationAttributes,
            IntPtr FileHandle);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        static extern int NtClose(IntPtr hObject);



        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtCreateProcessEx(
            out IntPtr prochandle,
            UInt32 desiredaccess,
            IntPtr objectattributes,
            IntPtr parentproc,
            UInt32 flags,
            IntPtr sechandle,
            IntPtr debugport,
            IntPtr exceptionport,
            bool injob

            );

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr buffer;
        }


        public static UNICODE_STRING stringToUNICODE_STRING(string name)
        {
            UNICODE_STRING us = new UNICODE_STRING();
            byte[] content = Encoding.UTF8.GetBytes(name);


            IntPtr baseptr = Marshal.StringToHGlobalUni(name);

            us.buffer = baseptr;
            us.Length = (ushort)((name.Length * 2) + 1);
            us.MaximumLength = (ushort)((name.Length * 2) + 2);

            return us;
        }


        public static IntPtr stringToUNICODE_STRINGPTR(string name)
        {
            UNICODE_STRING us = new UNICODE_STRING();
            byte[] content = Encoding.UTF8.GetBytes(name);


            IntPtr baseptr = Marshal.StringToHGlobalUni(name);

            us.buffer = baseptr;
            us.Length = (ushort)((name.Length * 2) + 1);
            us.MaximumLength = (ushort)((name.Length * 2) + 2);

            IntPtr temp = Marshal.AllocHGlobal(Marshal.SizeOf(us));
            Console.WriteLine(Marshal.SizeOf(us));

            Marshal.StructureToPtr(us, temp, true);

            return temp;
        }

        public static string UNICODE_STRINGToString(UNICODE_STRING us)
        {
            string res;

            res = Marshal.PtrToStringUni(us.buffer);

            return res;
        }


        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int RtlCreateProcessParametersEx(
        ref IntPtr ProcessParameters,
        ref UNICODE_STRING imagepath,
        ref UNICODE_STRING dllpath,
        ref UNICODE_STRING currentdir,
        ref UNICODE_STRING commandline,
        IntPtr environment,
        ref UNICODE_STRING windowtitle,
        ref UNICODE_STRING desktopinfo,
        IntPtr shellinfo,
        IntPtr runtimedata,
        UInt32 flags
        );



        [StructLayout(LayoutKind.Sequential)]
        public struct RtlUserProcessParameters
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Reserved1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public IntPtr[] Reserved2;
            public UNICODE_STRING ImagePathName;
            public UNICODE_STRING CommandLine;
            public IntPtr Environment;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 9)]
            public IntPtr[] Reserved3; // StartingPositionLeft, -Top, Width, Height, CharWidth, -Height, ConsoleTextAttributes, WindowFlags, ShowWindowFlags
            public UNICODE_STRING WindowTitle;
            public UNICODE_STRING DesktopName;
            public UNICODE_STRING ShellInfo;
            public UNICODE_STRING RuntimeData;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32 * 4)]
            public IntPtr[] Reserved4;
            public uint EnvironmentSize;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RtlUserProcessParameters64
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Reserved1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public IntPtr[] Reserved2;
            public UNICODE_STRING CurrentDirectoryPath;
            public UNICODE_STRING DllPath;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public IntPtr[] Reserved2b;
            public UNICODE_STRING ImagePathName;
            public UNICODE_STRING CommandLine;
            public UInt64 Environment;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 9)]
            public IntPtr[] Reserved3; // StartingPositionLeft, -Top, Width, Height, CharWidth, -Height, ConsoleTextAttributes, WindowFlags, ShowWindowFlags
            public UNICODE_STRING WindowTitle;
            public UNICODE_STRING DesktopName;
            public UNICODE_STRING ShellInfo;
            public UNICODE_STRING RuntimeData;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32 * 6)]
            public IntPtr[] Reserved4;
            public uint EnvironmentSize;
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

        #region declares
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
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




        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);

        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetProcAddress(
            IntPtr handle,
            string functionname
            );



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

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
         IntPtr hProcess,
         IntPtr lpBaseAddress,
         byte[] lpBuffer,
         Int32 nSize,
         ref UInt32 lpNumberOfBytesWritten
        );


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess,
   IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
   IntPtr lpParameter, uint dwCreationFlags, ref uint lpThreadId);



        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
   uint dwSize, uint flAllocationType, uint flProtect);



        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
               IntPtr hProcess,
               IntPtr lpBaseAddress,
               byte[] lpBuffer,
               Int32 nSize,
               ref uint lpNumberOfBytesRead);


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


        #endregion



        public static PROCESS_BASIC_INFORMATION GetProcessImageBase(IntPtr prochandle)
        {
            IntPtr imageptr = IntPtr.Zero;

            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();

            IntPtr temp = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)));

            uint length = 0;

            NtQueryInformationProcess(
                prochandle,
                0,
                temp,
                (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)),
                ref length
                );

            pbi = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(temp, typeof(PROCESS_BASIC_INFORMATION));

            Console.WriteLine(pbi.PebAddress.ToString("X"));
            byte[] bytebase = new byte[8];
            uint byteswritten = 0;

            ReadProcessMemory(prochandle,
                pbi.PebAddress + 0x10,
                bytebase,
                bytebase.Length,
                ref byteswritten
                );

            imageptr = (IntPtr)BitConverter.ToInt64(bytebase, 0);


            return pbi;

        }

        [DllImport("Userenv.dll", SetLastError = true)]
        public static extern bool CreateEnvironmentBlock(
            out IntPtr env,
            IntPtr token,
            bool inherit
            );


        [StructLayout(LayoutKind.Explicit, Size = 0x40)]
        public struct PEB
        {
            [FieldOffset(0x000)]
            public byte InheritedAddressSpace;
            [FieldOffset(0x001)]
            public byte ReadImageFileExecOptions;
            [FieldOffset(0x002)]
            public byte BeingDebugged;
            [FieldOffset(0x003)]
            public byte Spare;
            [FieldOffset(0x008)]
            public IntPtr Mutant;
            [FieldOffset(0x010)]
            public IntPtr ImageBaseAddress;     // (PVOID) 
            [FieldOffset(0x018)]
            public IntPtr Ldr;                  // (PPEB_LDR_DATA)
            [FieldOffset(0x020)]
            public IntPtr ProcessParameters;    // (PRTL_USER_PROCESS_PARAMETERS)
            [FieldOffset(0x028)]
            public IntPtr SubSystemData;        // (PVOID) 
            [FieldOffset(0x030)]
            public IntPtr ProcessHeap;          // (PVOID) 
            [FieldOffset(0x038)]
            public IntPtr FastPebLock;          // (PRTL_CRITICAL_SECTION)
        }


        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtCreateThreadEx(ref IntPtr threadHandle, UInt32 desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool inCreateSuspended, Int32 stackZeroBits, Int32 sizeOfStack, Int32 maximumStackSize, IntPtr attributeList);



    }
}
