using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices;
using System.IO;
using System.Collections;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ADautoenum
{
    class Program
    {

        public delegate string runall(string name);
        public static string GetKerberoastable(string domainname)
        {
            string res = "";
            StringWriter sw = new StringWriter();
            Console.WriteLine("-------Finding Kerberoastable Users-------");
            try
            {
                string DomainName = domainname;
                // testing.tech69.local
                string[] domain = DomainName.Split('.');
                for(int i = 0; i < domain.Length; i++)
                {
                    domain[i] = "DC=" + domain[i];
                }
                string dn = String.Join(",", domain);

                DirectoryEntry de = new DirectoryEntry(String.Format("LDAP://{0}",dn));

                DirectorySearcher ds = new DirectorySearcher();
                ds.SearchRoot = de;
                ds.Filter = "(&(objectclass=user)(serviceprincipalname=*))";

                foreach(SearchResult sr in ds.FindAll())
                {
                    sw.WriteLine("User: {0} from the domain: {1}", sr.Properties["samaccountname"][0],DomainName);
                    sw.WriteLine("SPN: {0}", sr.Properties["serviceprincipalname"][0]);
                }

                if (ds.FindAll().Count == 0)
                {
                    res = "Nothing Found";
                    
                }
                else
                {
                    res += sw.ToString();
                }

                
            }
            catch(Exception e)  {
                sw.WriteLine("Error occurred");
                res = sw.ToString();
                
            }
            return res;
        }


        public static string GetASREPRoastable(string domainname)
        {
            string res = "";
            StringWriter sw = new StringWriter();
            Console.WriteLine("------Finding ASREPRoastable users------");
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
                ds.Filter = "(&(objectclass=user)(useraccountcontrol>=4194304))";

                foreach (SearchResult sr in ds.FindAll())
                {
                    sw.WriteLine("User: {0} from Domain: {1}", sr.Properties["samaccountname"][0], DomainName);
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

                if (ds.FindAll().Count == 0)
                {
                    res = "Nothing Found";
                }
                else
                {
                    res = sw.ToString();
                }
            }
            catch(Exception e)
            {
                res = String.Format("Error occurred {0}",e.Message);
            }

            return res;
        }

        public static string GetDCSyncUsers(string domainname)
        {
            string res = "";
            StringWriter sw = new StringWriter();
            Console.WriteLine("------Finding DCSync capable users------");
            try
            {
                Hashtable ht = new Hashtable();
                ht.Add("DS-Replication-Get-Changes", "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2");
                ht.Add("DS-Replication-Get-Changes-All", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2");
                ht.Add("DS-Replication-Get-Changes-In-Filtered-Set", "89e95b76-444d-4c62-991a-0facbeda640c");
                ht.Add("DS-Replication-Manage-Topology", "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2");
                ht.Add("DS-Replication-Monitor-Topology", "f98340fb-7c5b-4cdb-a00b-2ebdfa115a96");
                ht.Add("DS-Replication-Synchronize", "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2");

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
                

                foreach(SearchResult sr in ds.FindAll())
                {
                    DirectoryEntry temp = sr.GetDirectoryEntry();

                    AuthorizationRuleCollection arc=  temp.ObjectSecurity.GetAccessRules(true,true,typeof(NTAccount));

                    foreach(ActiveDirectoryAccessRule ar in arc)
                    {
                        if (dn.Contains(temp.Name.ToString()))
                        {
                            foreach (DictionaryEntry dic in ht)
                            {
                                if (dic.Value.ToString() == ar.ObjectType.ToString())
                                {
                                    sw.WriteLine(ar.IdentityReference);
                                    sw.WriteLine(ar.ObjectType);
                                    sw.WriteLine(dic.Key.ToString());
                                }
                            }
                        }
                    }

                }

                res = sw.ToString();
            }
            catch (Exception e)
            {

            }
            return res;
        }

        public static string GetDescription(string domainname)
        {
            string res = "";
            StringWriter sw = new StringWriter();

            Console.WriteLine("------Finding Description field of Users------");
            try
            {
                
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
                ds.Filter = "(objectclass=user)";
                foreach(SearchResult sr in ds.FindAll())
                {
                    //Console.WriteLine(sr.Properties["description"][0]);
                    try
                    {
                        string description = sr.GetDirectoryEntry().Properties["description"][0].ToString();
                        if (description.Length > 0)
                        {
                            sw.WriteLine("Name: {0}",sr.Properties["samaccountname"][0]);
                            sw.WriteLine("Description: {0}",description);
                        }
                    }
                    catch { }
                }

                res = sw.ToString();

            }
            catch(Exception e)
            {
                res = e.Message;
            }


                return res;
        }

        static void Main(string[] args)
        {

            Domain d = Domain.GetCurrentDomain();
            string DomainName = d.Name;

            runall r = new runall(GetKerberoastable);
            
            r += GetASREPRoastable;
            r += GetDCSyncUsers;
            r += GetDescription;

            Delegate[] d2 = r.GetInvocationList();
            foreach(Delegate temp in d2)
            {
                Console.WriteLine(temp.DynamicInvoke(DomainName));
            }

            /*Console.WriteLine(GetKerberoastable(DomainName));
            Console.WriteLine();
            Console.WriteLine(GetASREPRoastable(DomainName));
            Console.WriteLine();
            
            Console.WriteLine(GetDCSyncUsers(DomainName));
            Console.WriteLine();
            Console.WriteLine(GetDescription(DomainName));*/
        }
    }
}
