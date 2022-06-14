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



        public static string GetGroupsPrivileges(string computername,string groupname)
        {
            string output = "";
            StringWriter sw = new StringWriter();

            uint mask = (uint)(

            LSA_AccessPolicy.POLICY_LOOKUP_NAMES 

            );
            IntPtr lsahandle = IntPtr.Zero;
            string systemname = null;
            LSA_OBJECT_ATTRIBUTES loa = new LSA_OBJECT_ATTRIBUTES();
            loa.Attributes = 0;
            loa.Length = 0;
            //loa.ObjectName = IntPtr.Zero;
            loa.SecurityDescriptor = IntPtr.Zero;
            loa.RootDirectory = IntPtr.Zero;
            loa.SecurityQualityOfService = IntPtr.Zero;

            int res = LsaOpenPolicy(
                ref systemname,
                ref loa,
                mask,
                ref lsahandle
                );

            Console.WriteLine(lsahandle);

            IntPtr unicodeptr = IntPtr.Zero;
            UInt64 count = 0;
            byte[] sid = null;
            uint cbsize = 0;
            StringBuilder domainname = new StringBuilder();
            uint domainlength = 0;
            int acctype = 0;

            int res2 = LookupAccountNameW(
                computername,
                groupname,
                sid,
                ref cbsize,
                domainname,
                ref domainlength,
                ref acctype
                );

            domainname = new StringBuilder((int)domainlength);
            sid = new byte[cbsize];

            LookupAccountNameW(
                computername,
                groupname,
                sid,
                ref cbsize,
                domainname,
                ref domainlength,
                ref acctype
                );

            
            IntPtr username = IntPtr.Zero;
            ConvertSidToStringSidW(sid, ref username);
            
            sw.WriteLine("Group: {0}, SID: {1}", groupname, Marshal.PtrToStringUni(username));


            int res1 = LsaEnumerateAccountRights(
                lsahandle,
                sid,
                ref unicodeptr,
                ref count
                );
            //Console.WriteLine("res1: {0}", res1);

           // Console.WriteLine("Rights count: {0}", count);

            for (ulong i = 0; i < count; i++)
            {
                LSA_UNICODE_STRING lus = (LSA_UNICODE_STRING)Marshal.PtrToStructure(unicodeptr, typeof(LSA_UNICODE_STRING));

                
                sw.Write(LSAUNICODEToString(lus) + ",");

                unicodeptr = (IntPtr)(unicodeptr.ToInt64() + Marshal.SizeOf(typeof(LSA_UNICODE_STRING)));

            }
            LsaClose(lsahandle);

            sw.WriteLine();
            output = sw.ToString();

            return output;
        }


        public static List<string> GetGroups()
        {
            List<string> groups = new List<string>();


            try
            {

                Forest f = Forest.GetCurrentForest();
                DomainCollection domains = f.Domains;
                foreach (Domain d in domains)
                {
                    string domainName = d.Name.ToString();
                    string[] dcs = domainName.Split('.');
                    for (int i = 0; i < dcs.Length; i++)
                    {
                        dcs[i] = "DC=" + dcs[i];

                    }

                    StringWriter sw = new StringWriter();

                    try
                    {
                        // DC=tech69,DC=local,DC=net 
                        DirectoryEntry de = new DirectoryEntry(String.Format("LDAP://{0}", String.Join(",", dcs)));
                        DirectorySearcher ds = new DirectorySearcher();
                        ds.SearchRoot = de;
                        ds.Filter = "(objectclass=group)";
                        foreach (SearchResult sr in ds.FindAll())
                        {
                            groups.Add(sr.Properties["samaccountname"][0].ToString());
                        }

                    }
                    catch { }
                }
            }
            catch { }

            return groups;
        }


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


        public static string PSIDtoSTRING(byte[] sid)
        {
            IntPtr username = IntPtr.Zero;

            ConvertSidToStringSidW(sid, ref username);
            return Marshal.PtrToStringUni(username);
        }


        public static string GetNetShares(string computername)
        {
            string output = "";
            StringWriter sw = new StringWriter();

            IntPtr bufptr = IntPtr.Zero;
            UInt32 entriesread = 0, totalentries = 0;
            //string computername = Environment.MachineName;
            int result = NetShareEnum(
                computername,
                503,
                ref bufptr,
                1000,
                ref entriesread,
                ref totalentries,
                IntPtr.Zero
                );

            OrderedDictionary SHARE_TYPES = new OrderedDictionary();
            SHARE_TYPES.Add(@"STYPE_SPECIAL- Special share reserved for interprocess communication (IPC$) or remote administration of the server", 2147483648);
            SHARE_TYPES.Add("STYPE_CLUSTER_DFS", 134217728);
            SHARE_TYPES.Add("STYPE_TEMPORARY", 1073741824);
            SHARE_TYPES.Add("STYPE_CLUSTER_SOFS", 67108864);
            SHARE_TYPES.Add("STYPE_CLUSTER_FS", 33554432);
            SHARE_TYPES.Add("STYPE_IPC", 3);
            SHARE_TYPES.Add("STYPE_DEVICE", 2);
            SHARE_TYPES.Add("STYPE_PRINTQ", 1);
            SHARE_TYPES.Add("STYPE_DISKTREE", 0);
            Console.WriteLine("Result is {0}", result);
            Console.WriteLine("Total entries are {0}", totalentries);
            for (int i = 0; i < totalentries; i++)
            {
                SHARE_INFO_503 s2 = (SHARE_INFO_503)Marshal.PtrToStructure(bufptr, typeof(SHARE_INFO_503));

                foreach (DictionaryEntry d in SHARE_TYPES)
                {
                    if (Int64.Parse(s2.shi503_type.ToString()) >= Int64.Parse(d.Value.ToString()))
                    {
                        sw.WriteLine(d.Key.ToString());
                        break;
                    }
                }
                sw.WriteLine("Netname: {0}", s2.shi503_netname);
                sw.WriteLine("Path: {0}", s2.shi503_path);
                sw.WriteLine("Current uses: {0}", s2.shi503_current_uses);
                sw.WriteLine("Remark: {0}", s2.shi503_remark);

                
                try
                {
                    string[] filenames = Directory.GetFiles(String.Format("\\\\{0}\\{1}", computername, s2.shi503_netname));
                    foreach (string filename in filenames)
                    {
                        sw.WriteLine("File: {0}", filename);
                    }
                    sw.WriteLine();
                }
                catch { }

                bufptr += Marshal.SizeOf(typeof(SHARE_INFO_503));
            }
            output = sw.ToString();

            return output;

        }



    }
}
