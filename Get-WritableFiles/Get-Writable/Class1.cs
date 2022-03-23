using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Permissions;
namespace Get_Writable
{
    public class Class1
    {

        public void GetWritable(string root)
        {
            /*
            try
            {
                string[] dirs = Directory.GetDirectories(root);

                foreach (string dir in dirs)
                {
                    GetWritable(dir);
                    try
                    {
                        FileStream fs = File.OpenWrite(dir+@"\s.txt");
                        Console.WriteLine("Writable Directory {0}", dir);
                        File.Delete(dir + @"\sample.txt");
                    }
                    catch { }
                }
            }
            catch { }*/
            /* try
             {
                 DriveInfo c = new DriveInfo(root);
                 DirectoryInfo dir = c.RootDirectory;
                 //Console.WriteLine(c.RootDirectory);

                 foreach(var i in dir.GetDirectories("*.*"))
                 {
                     var files = i.EnumerateFiles("*.*",SearchOption.AllDirectories);
                     foreach(var f in files)
                     {
                         // Console.WriteLine(f.FullName);
                         try
                         {
                             FileStream fs = File.Open(f.FullName, FileMode.Open, FileAccess.ReadWrite);
                             Console.WriteLine("Write Access on {0}",f.FullName);
                         }
                         catch { }

                         }
                 }

             }
             catch { }*/
            try
            {
               
                    var rootdirs = Directory.EnumerateDirectories(root);
                
                    foreach (var d in rootdirs)
                    {
                    try
                    {
                        var files = Directory.EnumerateFiles(d, "*", SearchOption.AllDirectories);
                        foreach (var file in files)
                        {
                            //Console.WriteLine(file);
                            try
                            {
                                FileStream fs = File.Open(file.ToString(), FileMode.Open, FileAccess.ReadWrite);
                                Console.WriteLine("Write Access on {0}",file);
                            }
                            catch { }
                            //FileStream fs = File.Open(file, FileMode.Open, FileAccess.ReadWrite);
                            // Console.WriteLine(file);
                        }
                    }
                    catch (UnauthorizedAccessException uae)
                    {
                        Console.WriteLine(uae.Message);
                    }

                }
                
            }
            catch { }
        
        }
        public static void Main(string[] args)
        {
            string rootpath = args[0];
            Class1 c = new Class1();
            c.GetWritable(args[0]);

           // Console.WriteLine("Press Any key to continue");
           // Console.ReadKey();
        }
    }
}
