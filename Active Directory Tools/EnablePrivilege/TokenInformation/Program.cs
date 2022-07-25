using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Security.Principal;

namespace TokenInformation
{
    class Program
    {
        public enum TOKEN_INFORMATION_CLASS {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            TokenIsAppContainer,
            TokenCapabilities,
            TokenAppContainerSid,
            TokenAppContainerNumber,
            TokenUserClaimAttributes,
            TokenDeviceClaimAttributes,
            TokenRestrictedUserClaimAttributes,
            TokenRestrictedDeviceClaimAttributes,
            TokenDeviceGroups,
            TokenRestrictedDeviceGroups,
            TokenSecurityAttributes,
            TokenIsRestricted,
            TokenProcessTrustLevel,
            TokenPrivateNameSpace,
            TokenSingletonAttributes,
            TokenBnoIsolation,
            TokenChildProcessFlags,
            TokenIsLessPrivilegedAppContainer,
            TokenIsSandboxed,
            MaxTokenInfoClass
        }


        [DllImport("Advapi32.dll")]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            int DesiredAccess,
            ref IntPtr TokenHandle
            );

        [DllImport("Advapi32.dll")]
        public static extern bool GetTokenInformation(
                IntPtr TokenHandle,
                TOKEN_INFORMATION_CLASS TokenInformationClass,
                IntPtr TokenInformation,
                int TokenInformationLength,
                ref int ReturnLength
                );


        [StructLayout(LayoutKind.Sequential)]
        public struct SID_IDENTIFIER_AUTHORITY
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public byte[] value;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID
        {

            public byte Revision;
            public byte SubAuthorityCount;
            public SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [DllImport("Advapi32.dll")]
        public static extern bool ConvertSidToStringSidW(
            IntPtr sid,
           ref IntPtr sb
            );


        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_GROUPS
        {

            public int GroupCount;
            //[MarshalAs(UnmanagedType.ByValArray,SizeConst =1)]
            public IntPtr Groups;
        }

        [DllImport("Kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);


        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_OWNER{
            public IntPtr Owner;
            }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIMARY_GROUP
        {
            public IntPtr Group;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_ELEVATION
        {
            public UInt32 TokenIsElevated;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;

        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {

            public LUID Luid;
            public int Attributes;

        }

        


        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray,SizeConst =30)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES_SINGLE
        {
            public int PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }


        [DllImport("Advapi32.dll")]
        public static extern bool LookupPrivilegeNameW(
            string lpSystemName,
             IntPtr lpLuid,
            [param:MarshalAs(UnmanagedType.LPWStr)] StringBuilder lpName,
            ref int cchName
            );



        [StructLayout(LayoutKind.Sequential,Pack =1)]
        public struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        [DllImport("Advapi32.dll")]
        public static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            [param:MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
            IntPtr NewState,
            int BufferLength,
            IntPtr PreviousState,
            IntPtr ReturnLength
            );

    public static void Main(string[] args)
        {
            int TOKEN_QUERY = 0x0008;

        IntPtr procHandle = Process.GetCurrentProcess().Handle;

            IntPtr tokenHandle = IntPtr.Zero;

            bool res =OpenProcessToken(
                procHandle,
                TOKEN_QUERY| 0x00000020,
                ref tokenHandle
                );
            Console.WriteLine(tokenHandle);

            // Getting Length of tokenuser structure
            int structlength = 0;
            bool temp =GetTokenInformation(
                tokenHandle,
                TOKEN_INFORMATION_CLASS.TokenUser,
                IntPtr.Zero,
                structlength,
                ref structlength
                );
            Console.WriteLine(structlength);


            int ownerlength = 0;
            bool temp2 = GetTokenInformation(
                tokenHandle,
                TOKEN_INFORMATION_CLASS.TokenGroups,
                IntPtr.Zero,
                ownerlength,
                ref ownerlength
                );
            Console.WriteLine("Owner Length {0}",ownerlength);

            // Allocating memory of size structlength to intptr
            IntPtr tokenuser = Marshal.AllocHGlobal(structlength);
           // IntPtr groupuser = Marshal.AllocHGlobal(grouplength);
            bool temp3 =GetTokenInformation(
                tokenHandle,
                TOKEN_INFORMATION_CLASS.TokenUser,
                tokenuser,
                structlength,
                ref structlength
                );

           TOKEN_USER tu = (TOKEN_USER) Marshal.PtrToStructure(tokenuser, typeof(TOKEN_USER));
            // StringBuilder sb = new StringBuilder(100);
            // Console.WriteLine(Encoding.UTF8.GetString(tu.User.Sid.IdentifierAuthority.value));
            IntPtr sb = IntPtr.Zero;
            bool t= ConvertSidToStringSidW(tu.User.Sid,ref sb);


            string sid =Marshal.PtrToStringUni(sb);
            Console.WriteLine(sid);

            SecurityIdentifier s = new SecurityIdentifier(sid);
            string username =s.Translate(typeof(NTAccount)).ToString();
            Console.WriteLine(username);

            // Console.WriteLine(sb.ToString());


            IntPtr owner = Marshal.AllocHGlobal(ownerlength);

            GetTokenInformation(
                tokenHandle,
                TOKEN_INFORMATION_CLASS.TokenPrimaryGroup,
                owner,
                ownerlength,
                ref ownerlength
                );

            TOKEN_PRIMARY_GROUP tokenowner = (TOKEN_PRIMARY_GROUP)Marshal.PtrToStructure(owner, typeof(TOKEN_PRIMARY_GROUP));

            Console.WriteLine(tokenowner.Group);

            IntPtr sb2 = IntPtr.Zero;
            bool t2 = ConvertSidToStringSidW(tokenowner.Group, ref sb2);


            string sid2 = Marshal.PtrToStringUni(sb2);
            Console.WriteLine(sid2);

            SecurityIdentifier s2 = new SecurityIdentifier(sid2);
            string username2 = s2.Translate(typeof(NTAccount)).ToString();
            Console.WriteLine(username2);

            Console.WriteLine("Checking if token has elevated privileges");

            IntPtr elevated = Marshal.AllocHGlobal(4);
            int elevatedlength = 4;
            GetTokenInformation(
                tokenHandle,
                TOKEN_INFORMATION_CLASS.TokenElevation,
                elevated,
                4,
                ref elevatedlength
                );

            Console.WriteLine(elevatedlength);
            TOKEN_ELEVATION te = (TOKEN_ELEVATION)Marshal.PtrToStructure(elevated, typeof(TOKEN_ELEVATION));
            if (te.TokenIsElevated!=0)
            {
                Console.WriteLine(te.TokenIsElevated);
                Console.WriteLine("Elevated token");
            }
            else
            {
                Console.WriteLine("Token is not elevated");
            }



            int privlength = 0;

            GetTokenInformation(
                tokenHandle,
                TOKEN_INFORMATION_CLASS.TokenPrivileges,
                IntPtr.Zero,
                privlength,
                ref privlength
                );

            Console.WriteLine(privlength);
            IntPtr privptr = Marshal.AllocHGlobal(privlength);

            GetTokenInformation(
                tokenHandle,
                TOKEN_INFORMATION_CLASS.TokenPrivileges,
                privptr,
                privlength,
                ref privlength
                );

            TOKEN_PRIVILEGES tp = (TOKEN_PRIVILEGES) Marshal.PtrToStructure(privptr, typeof(TOKEN_PRIVILEGES));
            // 12 is size of LUID AND ATTRIBUTES
            Console.WriteLine(tp.PrivilegeCount);
            

            IntPtr laaptr= new IntPtr(privptr.ToInt64() + sizeof(int));

            LUID_AND_ATTRIBUTES laa = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(laaptr, typeof(LUID_AND_ATTRIBUTES));

            Console.WriteLine(laa.Luid.LowPart);
            Console.WriteLine(laa.Luid.HighPart);

            IntPtr luidptr = Marshal.AllocHGlobal(Marshal.SizeOf(laa.Luid));

            
            Marshal.StructureToPtr(laa.Luid, luidptr, true);
            int cchName = 100;
            StringBuilder sb3 = new StringBuilder(100);
            bool temp11 = LookupPrivilegeNameW(
                null,
                luidptr,
                sb3,
                ref cchName
                );

            Console.WriteLine(Marshal.GetLastWin32Error());
            Console.WriteLine(sb3.ToString());


            for (int i = 1; i < tp.PrivilegeCount; i++)
            {

                IntPtr nextptr = new IntPtr(laaptr.ToInt64() + i * Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES)));

                LUID_AND_ATTRIBUTES laa2 = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(nextptr, typeof(LUID_AND_ATTRIBUTES));

                Console.WriteLine("Luid low {0}",laa2.Luid.LowPart);
                Console.WriteLine("Luid high {0}",laa2.Luid.HighPart);

                IntPtr luidptr2 = Marshal.AllocHGlobal(Marshal.SizeOf(laa2.Luid));
                Marshal.StructureToPtr(laa2.Luid, luidptr2, true);
                int cchName2 = 100;
                StringBuilder sb32 = new StringBuilder(100);
                bool temp112 = LookupPrivilegeNameW(
                    null,
                    luidptr2,
                    sb32,
                    ref cchName2
                    );

                
                Console.WriteLine(sb32.ToString());
                Console.WriteLine("Adjusting privileges");
                int temp1 = 0;

                TOKEN_PRIVILEGES_SINGLE temptp = new TOKEN_PRIVILEGES_SINGLE();
                temptp.PrivilegeCount = 1;
                temptp.Privileges = new LUID_AND_ATTRIBUTES[1];
                temptp.Privileges[0].Luid = laa2.Luid;
                temptp.Privileges[0].Attributes = 2;

                IntPtr temptpptr = Marshal.AllocHGlobal(Marshal.SizeOf(temptp));
                Marshal.StructureToPtr(temptp, temptpptr, true);

                AdjustTokenPrivileges(
                       tokenHandle,
                       false,   
                       temptpptr,
                       0,
                       IntPtr.Zero,
                       IntPtr.Zero

                       );
                Console.WriteLine("Error->{0}",Marshal.GetLastWin32Error());

            }

   

            //CloseHandle(procHandle);
            CloseHandle(tokenHandle);
            Console.WriteLine("press any key to continue");
            Console.ReadKey();
        }
     }

    
}
