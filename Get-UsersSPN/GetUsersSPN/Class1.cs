using System;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Collections;

namespace GetUsersSPN
{
    public class Class1
    {
        public void GetSPNs()
        {
            Forest f = Forest.GetCurrentForest();
            DomainCollection dcs = f.Domains;
            ArrayList domains = new ArrayList();

            foreach(Domain d in dcs)
            {
                domains.Add(d.Name.ToString());

                string domainName = d.Name.ToString();
                string[] dn = domainName.Split('.');
                for(int i = 0; i < dn.Length; i++)
                {
                    dn[i] = "DC=" + dn[i];
                    //Console.WriteLine(dn[i]);
                }

                DirectoryEntry de = new DirectoryEntry(String.Format("LDAP://{0}", String.Join(",", dn)));

                DirectorySearcher ds = new DirectorySearcher();
                ds.SearchRoot = de;
                ds.Filter = "(&(objectclass=user)(serviceprincipalname=*))";

                foreach(SearchResult sr in ds.FindAll())
                {
                    Console.WriteLine("User: {0} from the Domain: {1}",sr.Properties["samaccountname"][0],domainName);
                    Console.WriteLine("SPN: {0}",sr.Properties["serviceprincipalname"][0]);
                    Console.WriteLine();
                }

              
            }

        }
        public static void Main(string[] args)
        {
            try
            {
                Class1 c = new Class1();
                c.GetSPNs();
            }
            catch { }
        }
    }
}
