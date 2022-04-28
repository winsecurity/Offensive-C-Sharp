using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace EnablePrivileges
{
    class Program
    {

        [DllImport("Kernel32.dll")]
        public static extern UInt32 GetCurrentProcessId();


        [DllImport("Kernel32.dll")]
        public static extern IntPtr OpenProcess(
            UInt32 dwDesiredAccess,
            bool bInheritHandle,
            UInt32 dwProcessId
            );


        [DllImport("Kernel32.dll")]

        public static extern int OpenProcessToken(
            IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            ref UIntPtr TokenHandle
            );


        [DllImport("Kernel32.dll")]
        public static extern UInt32 GetLastError();


        [DllImport("Advapi32.dll")]
        public static extern int DuplicateTokenEx(
            UIntPtr ExistingTokenHandle,
            int dwDesiredAccess,
            IntPtr lpTokenAttributes,
            int ImpersonationLevel,
            int TokenType,
            ref IntPtr DuplicateTokenHandle
            );

       

        [StructLayout(LayoutKind.Sequential)]
        internal struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }


        [StructLayout(LayoutKind.Sequential)]
        internal struct LUID
        {
            public UInt32 LowPart;
            public long HighPart;
        }


        [StructLayout(LayoutKind.Sequential)]
        internal struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray,SizeConst =1)]
            public LUID_AND_ATTRIBUTES[] Privileges ;
           
        }

        [DllImport("Advapi32.dll")]
        public static extern int AdjustTokenPrivileges(
             UIntPtr TokenHandle,
            bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState,
            UInt32 BufferLength,
            IntPtr PreviousState,
            IntPtr ReturnLength
            );


        [DllImport("Advapi32.dll")]
        public static extern int LookupPrivilegeValueW(
            [param:MarshalAs(UnmanagedType.LPWStr)] string lpSystemName,
            [param: MarshalAs(UnmanagedType.LPWStr)] string lpName,
            ref LUID lpLuid
            );


        [DllImport("Advapi32.dll")]
        public static extern int LookupPrivilegeNameW(
            [param: MarshalAs(UnmanagedType.LPWStr)] string lpSystemName,
            ref LUID lpLuid,
            [param: MarshalAs(UnmanagedType.LPWStr)] StringBuilder lpName,
            ref UInt32 cchName
            );

        static void Main(string[] args)
        {

            Console.WriteLine("Enabling privileges");
            
            IntPtr phandle =OpenProcess(0x000F0000 | 0x00100000 | 0xFFFF,
                false,
                GetCurrentProcessId()
                );
            UIntPtr tokenhandle = UIntPtr.Zero;
            int res = OpenProcessToken(
                phandle,
                0x00000020| 0x00000008,
                ref tokenhandle
                );
            Console.WriteLine(phandle);

            LUID l = new LUID();
            
            
            StringBuilder sb = new StringBuilder(1000);
            UInt32 cchName = 100;

            int result= LookupPrivilegeValueW(
                null,
                "SeDebugPrivilege",
                 ref l
                );

            Console.WriteLine(result);
            



            int res2= LookupPrivilegeNameW(null, ref l, sb, ref cchName);
            Console.WriteLine(sb.ToString());

            // 20 low  0 high for sedebug
            Console.WriteLine(l.LowPart);
            Console.WriteLine(l.HighPart);

            LUID_AND_ATTRIBUTES la = new LUID_AND_ATTRIBUTES();
            la.Luid = l;
            la.Attributes = 2;

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.Privileges = new LUID_AND_ATTRIBUTES[1];
            tp.Privileges[0] = la;
            //tp.Privileges[0] = la;
            
            tp.PrivilegeCount = 1;

            UInt32 test = 0;
            int temp1 =AdjustTokenPrivileges(
                  tokenhandle,
                false,
                ref tp,
                0,
                IntPtr.Zero,
                IntPtr.Zero
                ) ;
            Console.WriteLine(GetLastError());
            Console.WriteLine("press any key to continue");
            Console.ReadKey();
        }
    }
}
