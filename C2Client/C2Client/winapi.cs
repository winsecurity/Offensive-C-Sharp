using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.IO;

namespace C2Client
{
   
    class winapi
    {

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
        public static LSA_UNICODE_STRING stringToLSAUNICODE(string test)
        {

            IntPtr stringptr = Marshal.StringToHGlobalUni(test);
            LSA_UNICODE_STRING lsau = new LSA_UNICODE_STRING();
            lsau.Buffer = stringptr;
            lsau.Length = (ushort)(test.Length * UnicodeEncoding.CharSize);
            lsau.MaximumLength = (ushort)((test.Length + 1) * UnicodeEncoding.CharSize);
            return lsau;
        }


        public static string LSAUNICODEToString(LSA_UNICODE_STRING lsau)
        {
            char[] test = new char[lsau.MaximumLength];
            Marshal.Copy(lsau.Buffer, test, 0, lsau.Length / UnicodeEncoding.CharSize);
            return new string(test);
        }
        public static string Getlogonsessions()
        {
            string output = "";
            UInt64 count = 0;
            StringWriter sw = new StringWriter();

            IntPtr luidptr = IntPtr.Zero;
            int res = LsaEnumerateLogonSessions(ref count, ref luidptr);

            if (res == 0)
            {
                //Console.WriteLine(count);

                for (ulong i = 0; i < count; i++)
                {

                    LUID l = (LUID)Marshal.PtrToStructure(luidptr, typeof(LUID));

                    //Console.WriteLine("Low part: {0}",l.LowPart);
                    //Console.WriteLine("High part: {0}",l.HighPart);
                    IntPtr sdata = IntPtr.Zero;
                    int res1 = LsaGetLogonSessionData(luidptr, ref sdata);

                    if (res1 == 0)
                    {
                        SECURITY_LOGON_SESSION_DATA s = (SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(sdata, typeof(SECURITY_LOGON_SESSION_DATA));

                        if (s.UserName.Length > 0)
                        {
                            sw.WriteLine("Username: {0}", LSAUNICODEToString(s.UserName));
                            sw.WriteLine("Domain: {0}", LSAUNICODEToString(s.LoginDomain));
                            sw.WriteLine("Logon server: {0}", LSAUNICODEToString(s.LogonServer));
                        }
                    }

                    LsaFreeReturnBuffer(sdata);
                    luidptr = (IntPtr)luidptr.ToInt64() + Marshal.SizeOf(typeof(LUID));


                }

                LsaFreeReturnBuffer(luidptr);
            }
            sw.WriteLine("Logon sessions count: {0}", count);

            output = sw.ToString();
            return output;
        }

    }
}
