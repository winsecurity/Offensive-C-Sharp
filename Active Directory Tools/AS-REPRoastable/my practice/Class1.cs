using System;
using System.Collections;
using System.Collections.Generic;

using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices;

namespace my_practice
{

    public class Class1
    {
        

        public void GetASREPRoastable()
        {

            // User access control values
            List<string> l = new List<string>();
            l.Add(""); l.Add("ACCOUNTDISABLE"); l.Add(""); l.Add("HOMEDIR_REQUIRED");
            l.Add("LOCKOUT"); l.Add("PASSWD_NOTREQD"); l.Add("PASSWD_CANT_CHANGE");
            l.Add("ENCRYPTED_TEXT_PWD_ALLOWED"); l.Add("TEMP_DUPLICATE_ACCOUNT");
            l.Add("NORMAL_ACCOUNT"); l.Add(""); l.Add("INTERDOMAIN_TRUST_ACCOUNT");
            l.Add("WORKSTATION_TRUST_ACCOUNT"); l.Add("SERVER_TRUST_ACCOUNT");l.Add(""); l.Add("");
            l.Add("DONT_EXPIRE_PASSWORD"); l.Add("MNS_LOGON_ACCOUNT");
            l.Add("SMARTCARD_REQUIRED"); l.Add("TRUSTED_FOR_DELEGATION");
            l.Add("NOT_DELEGATED"); l.Add("USE_DES_KEY_ONLY");
            l.Add("DONT_REQ_PREAUTH"); l.Add("PASSWORD_EXPIRED");
            l.Add("TRUSTED_TO_AUTH_FOR_DELEGATION");
            //l.Reverse();


            // Fetching all domains
            Forest f = Forest.GetCurrentForest();
            DomainCollection domains = f.Domains;
            foreach(Domain d in domains)
            {

                // tech69.local  , DC=tech69,DC=local
                string domainName = d.Name.ToString();
                string[] dcs = domainName.Split('.');

                for(int i = 0; i < dcs.Length; i++)
                {
                    dcs[i] = "DC=" + dcs[i];
                    //Console.WriteLine(dcs[i]);
                }

                // DC=tech69,DC=local,DC=net 
                DirectoryEntry de = new DirectoryEntry(String.Format("LDAP://{0}",String.Join(",",dcs)));
                DirectorySearcher ds = new DirectorySearcher();
                ds.SearchRoot = de;
                ds.Filter = "(&(objectclass=user)(!(objectclass=computer))(useraccountcontrol>=4194304))";
                foreach(SearchResult sr in ds.FindAll())
                {
                    Console.WriteLine("User: {0} from Domain: {1}", sr.Properties["samaccountname"][0],domainName);
                    Console.WriteLine("UserAccountControl: {0}",sr.Properties["useraccountcontrol"][0]);
                    int uac = Convert.ToInt32(sr.Properties["useraccountcontrol"][0]);
                    string uac_binary = Convert.ToString(uac, 2);
                    List<string> flags = new List<string>();
                    //Console.WriteLine(l.Count);
                    //Console.WriteLine(uac_binary.Length);
                    for(int i =0; i <uac_binary.Length; i++)
                    {
                        int result = uac & Convert.ToInt32(Math.Pow(2, i));
                        if (result != 0)
                       {
                           //Console.WriteLine(l[i]);
                           flags.Add(l[i]);
                       }
                      
                    }
                    foreach (string temp in flags)
                    {
                       Console.WriteLine(temp);
                    }
                    Console.WriteLine();
                }

            }

        }

        public static void Main(string[] args)
        {

            // 4194304
            
            
            try
            {
                Class1 c = new Class1();
                c.GetASREPRoastable();
            }
            catch { }
            //Console.ReadKey();

        }
    }
}
