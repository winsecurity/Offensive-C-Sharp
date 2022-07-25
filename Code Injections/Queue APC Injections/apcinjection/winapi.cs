using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;



namespace apcinjection
{
    public partial class Program
    {

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(
            IntPtr prochandle,
            IntPtr baseaddress,
            UInt32 dwSize,
            UInt32 flAllocationType,
            UInt32 flProtect
            );



        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateThread(
            IntPtr lpThreadAttributes,
            UInt32 dwStackSize,
            IntPtr baseaddress,
            IntPtr functionparameter,
            UInt32 creationflags,
            out UInt32 threadid
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
        public static extern IntPtr OpenProcess(
            UInt32 dwDesiredAccess,
            bool inherithandle,
            UInt32 dwProcessId
            );


        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr prochandle,
            IntPtr baseaddress,
            byte[] buffer,
            UInt32 size,
            out UInt32 byteswritten
            );


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
        public  struct PROCESS_INFORMATION
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


        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool CreateProcessW(
            [param:MarshalAs(UnmanagedType.LPWStr)] string applicationpath,
            [param: MarshalAs(UnmanagedType.LPWStr)] string commandline,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool inherithandles,
            UInt32 dwCreationFlags,
            IntPtr lpEnvironment,
            [param: MarshalAs(UnmanagedType.LPWStr)] string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION pinfo
            );

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern UInt32 ResumeThread(
            IntPtr threadhandle
            );


        [DllImport("ntdll.dll")]
        public static extern int NtAlertThread(
            IntPtr threadhandle
            );


        [DllImport("ntdll.dll")]
        public static extern int NtTestAlert();

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentThread();



    }
}
