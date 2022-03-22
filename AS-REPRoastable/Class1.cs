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

            Forest f = Forest.GetCurrentForest();
            Console.WriteLine("Forest Name: {0}",f.Name);
            DomainCollection dcs = f.Domains;
            foreach(Domain d in dcs)
            {
                Console.WriteLine("Domain Found {0}",d.Name);
            }
            Console.WriteLine();
            foreach (Domain d in dcs)
            {

                //Getting Domain Name
                //DirectoryContext d = new DirectoryContext(DirectoryContextType.Domain);
                //string domainName = Domain.GetDomain(d).ToString();
                string domainName = d.Name.ToString();
                // now domainName contains tech69.local;

                string[] d1 = domainName.Split('.');
                // d1=tech69 d2=local
                string[] domains = new string[d1.Length];
                for(int i = 0; i < domains.Length; i++)
                {
                    domains[i] = "DC=" + d1[i];
                    //Console.WriteLine(domains[i]);
                }

                DirectoryEntry de = new DirectoryEntry(String.Format("LDAP://{0}",String.Join(",",domains)));
                DirectorySearcher ds = new DirectorySearcher();
                ds.SearchRoot = de;
                ds.Filter = "(&(objectclass=user)(!(objectclass=computer))(useraccountcontrol>=4194304))";
                if (ds.FindAll() != null)
                {
                    Console.WriteLine("[+] Look at these users of domain {0}",domainName);
                    //Console.WriteLine();
                }
                foreach (SearchResult sr in ds.FindAll())
                {
                    Console.WriteLine("User: {0}", sr.Properties["samaccountname"][0]);
                    Console.WriteLine("UserAccountControl: {0}", sr.Properties["useraccountcontrol"][0]);
                   // Console.WriteLine();
                }
            }

        }
       
        public static void Main(string[] args)
        {

            //string domainname = args[0];
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
