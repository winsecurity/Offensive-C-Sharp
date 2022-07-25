using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Security.AccessControl;
using System.Security.Principal;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.AccountManagement;
using System.Security.AccessControl;
using System.Collections;
using System.IO;

namespace ACL101
{
    class Program
    {

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
        static void Main(string[] args)
        {
            try
            {
                Forest f = Forest.GetCurrentForest();
                string cmd;
                DomainCollection domains = f.Domains;
                cmd = "";
                foreach (Domain d in domains)
                {
                    string domainName = d.Name;

                    string[] dcs = domainName.Split('.');
                    for (int i = 0; i < dcs.Length; i++)
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

                Console.WriteLine(cmd);
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
            }
            /*ActiveDirectorySecurity ads = new ActiveDirectorySecurity();

            //NTAccount test = new NTAccount("test2");
            // SecurityIdentifier sid = (SecurityIdentifier)test.Translate(typeof(SecurityIdentifier));
           

            DirectoryEntry de = new DirectoryEntry("LDAP://DC=tech69,DC=local");
            
                DirectorySearcher ds = new DirectorySearcher();
            ds.SearchRoot = de;
            // ds.Filter = "(objectclass=user)";

            Hashtable ht = new Hashtable();
            ht.Add("DS-Replication-Get-Changes", "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2");
            ht.Add("DS-Replication-Get-Changes-All", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2");
            ht.Add("DS-Replication-Get-Changes-In-Filtered-Set", "89e95b76-444d-4c62-991a-0facbeda640c");
            ht.Add("DS-Replication-Manage-Topology", "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2");
            ht.Add("DS-Replication-Monitor-Topology", "f98340fb-7c5b-4cdb-a00b-2ebdfa115a96");
            ht.Add("DS-Replication-Synchronize", "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2");


            foreach (SearchResult sr in ds.FindAll())
            {
                DirectoryEntry temp = sr.GetDirectoryEntry();
                ActiveDirectorySecurity ads2 = temp.ObjectSecurity;
                string sid = ads2.GetSecurityDescriptorSddlForm(AccessControlSections.All);

                AuthorizationRuleCollection arc = temp.ObjectSecurity.GetAccessRules(true, true, typeof(NTAccount));

                

                if (temp.Name == @"DC=tech69")
                {
                    foreach (ActiveDirectoryAccessRule a in arc)
                    {

                        
                            
                            foreach(DictionaryEntry d in ht)
                            {
                                if(d.Value.ToString() == a.ObjectType.ToString())
                                {
                                Console.WriteLine(a.IdentityReference);
                                Console.WriteLine("Object type " + a.ObjectType);
                                Console.WriteLine(temp.Name);
                                Console.WriteLine(d.Key);
                                Console.WriteLine(a.ObjectFlags);
                                


                                Console.WriteLine(a.ActiveDirectoryRights);
                                Console.WriteLine(a.AccessControlType);
                                Console.WriteLine();
                            }
                            }
                            
                           // Console.WriteLine(a.InheritanceType);
                           // Console.WriteLine(a.PropagationFlags);
                           // Console.WriteLine(a.InheritanceFlags);

                        }

                    
                }
               // Console.WriteLine();
            }


            PrincipalContext p = new PrincipalContext(ContextType.Domain, "tech69.local");
            UserPrincipal users = new UserPrincipal(p);

            PrincipalSearcher sr2 = new PrincipalSearcher(users);

            /*foreach (var user in sr2.FindAll())
            {
                Console.WriteLine(user.SamAccountName);
                Console.WriteLine(user.Sid);
                Console.WriteLine(user.);
            }

        
                byte[] b = new byte[user.Sid.BinaryLength];
                user.Sid.GetBinaryForm(b, 0);
                
                ads.SetSecurityDescriptorBinaryForm(b);
                AuthorizationRuleCollection arc = ads.GetAccessRules(true, true, typeof(SecurityIdentifier));

                foreach(ActiveDirectoryAccessRule a in arc)
                {
                    Console.WriteLine(a.ActiveDirectoryRights);
                }
                Console.WriteLine();
                
            }*/
        }
    }
}
