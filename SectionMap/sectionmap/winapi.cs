using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace sectionmap
{



    public partial class Program
    {

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtCreateSection(
            out IntPtr sectionhandle,
            UInt32 desiredaccess,
            IntPtr objectattributes,
            ref UInt32 MaximumSize,
            UInt32 SectionPageProtection,
            UInt32 AllocationAttributes,
            IntPtr filehandle
            );


        [DllImport("ntdll.dll")]
        public static extern int NtClose(IntPtr handle);


        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            UIntPtr ZeroBits,
            UIntPtr CommitSize,
            ref ulong SectionOffset,
            ref uint ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect
            );


        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtUnmapViewOfSection(
            IntPtr prochandle,
            IntPtr baseaddress
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
        public static extern IntPtr CreateRemoteThread(
            IntPtr prochandle,
            IntPtr lpThreadAttributes,
            UInt32 stacksize,
            IntPtr lpStartAddress,
            IntPtr functionparameter,
            UInt32 dwCreationFlags,
            out UInt32 lpThreadId
            );


        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            UInt32 dwDesiredAccess,
            bool inherithandle,
            UInt32 dwProcessId
            );


        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int RtlCreateUserThread(
            IntPtr prochandle,
            IntPtr secatrributes,
            bool createsuspended,
            ulong stackzerobits,
            out ulong stackreserved,
            out ulong stackcommit,
            IntPtr baseaddress,
            IntPtr functionparameter,
            out IntPtr threadhandle,
            out UInt32 clientid
            );



    }
}
