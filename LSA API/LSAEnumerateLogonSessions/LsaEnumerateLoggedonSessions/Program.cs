using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace LsaEnumerateLoggedonSessions
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        public  struct LSA_LAST_INTER_LOGON_INFO
        {
           public LARGE_INTEGER LastSuccessfulLogon;
           public LARGE_INTEGER LastFailedLogon;
           public ulong FailedAttemptCountSinceLastSuccessfulLogon;
        }

        [StructLayout(LayoutKind.Explicit,Size =8)]
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

        public static LSA_UNICODE_STRING StringToLSAUNICODE(string test)
        {
            IntPtr stringptr = Marshal.StringToHGlobalUni(test);

            LSA_UNICODE_STRING lsaunicode = new LSA_UNICODE_STRING();
            lsaunicode.Buffer = stringptr;
            lsaunicode.Length = (UInt16)(test.Length * UnicodeEncoding.CharSize);
            lsaunicode.MaximumLength = (UInt16)((test.Length+1) * UnicodeEncoding.CharSize);
            return lsaunicode;
        }


        public static string LSAUNICODEToString(LSA_UNICODE_STRING lsau)
        {
            char[] test = new char[lsau.MaximumLength];
            if (lsau.Length % 2 == 1)
            {
                lsau.Length = (ushort)(lsau.Length + 1);
            }
            Marshal.Copy(lsau.Buffer, test, 0, lsau.Length/UnicodeEncoding.CharSize);
            return new string(test);

        }


        [DllImport("Secur32.dll")]
        public static extern int LsaGetLogonSessionData(
            IntPtr logonid,
            ref IntPtr ppLogonSessionData
            );

        static void Main(string[] args)
        {
            UInt64 count = 0;
            IntPtr temp = IntPtr.Zero;
            int res = LsaEnumerateLogonSessions(ref count, ref temp);
            Console.WriteLine(temp);

            //IntPtr p =(IntPtr) Marshal.ReadInt32(temp);
            for (ulong i = 0; i < count; i++)
            {
                LUID l = (LUID)Marshal.PtrToStructure(temp, typeof(LUID));
                // Console.WriteLine("lower: {0}",l.LowPart);
                //Console.WriteLine(l.HighPart);

                IntPtr data = IntPtr.Zero;
                int res1 = LsaGetLogonSessionData(temp, ref data);
                //Console.WriteLine("result: {0}",res1);
                if (data != IntPtr.Zero)
                {
                    SECURITY_LOGON_SESSION_DATA sdata = (SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(data, typeof(SECURITY_LOGON_SESSION_DATA));
                    if (sdata.Sid != IntPtr.Zero)
                    {
                        try
                        {
                            Console.WriteLine("Username: {0}",LSAUNICODEToString(sdata.UserName));
                            Console.WriteLine("Logon Server: {0}",LSAUNICODEToString(sdata.LogonServer));
                            Console.WriteLine("UPN: {0}",LSAUNICODEToString(sdata.Upn));
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e.Message);
                        }
                    }
                }

                LsaFreeReturnBuffer(data);
                temp =(IntPtr) (temp.ToInt64() + Marshal.SizeOf(typeof(LUID)));
            }
            Console.WriteLine(count);

            LsaFreeReturnBuffer(temp);
            //Console.ReadKey();

        }
    }
}
