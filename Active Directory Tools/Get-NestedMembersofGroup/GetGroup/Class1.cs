using System;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;

namespace GetGroup
{
    public class Class1
    {

        public void GetAllMembers(string groupName,string domainName)
        {
            PrincipalContext p = new PrincipalContext(ContextType.Domain, domainName);
           GroupPrincipal gp = GroupPrincipal.FindByIdentity(p,groupName);
            foreach(Principal group in gp.GetMembers())
            {   
                if (group.StructuralObjectClass == "user")
                {
                    Console.WriteLine("User: {0} is memberOf {1}",group.Name,groupName);
                }
                if (group.StructuralObjectClass == "group")
                {
                    Console.WriteLine("Group: {0} is memberOf {1}",group.Name,groupName);
                    GetAllMembers(group.Name, domainName);
                }
            }
        }
        
        
        public static void Main(string[] args)
        {
            try
            {
                string groupname = args[0];
                string domainname = args[1];

                Class1 c = new Class1();
                c.GetAllMembers(groupname, domainname);
            }
            catch { }
            //Console.ReadKey();
        }
    }
}
