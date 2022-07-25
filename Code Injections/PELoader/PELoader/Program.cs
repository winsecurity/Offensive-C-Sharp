using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.IO;

namespace PELoader
{

    class Program
    {

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] e_magic;       // Magic number
            public UInt16 e_cblp;    // Bytes on last page of file
            public UInt16 e_cp;      // Pages in file
            public UInt16 e_crlc;    // Relocations
            public UInt16 e_cparhdr;     // Size of header in paragraphs
            public UInt16 e_minalloc;    // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;    // Maximum extra paragraphs needed
            public UInt16 e_ss;      // Initial (relative) SS value
            public UInt16 e_sp;      // Initial SP value
            public UInt16 e_csum;    // Checksum
            public UInt16 e_ip;      // Initial IP value
            public UInt16 e_cs;      // Initial (relative) CS value
            public UInt16 e_lfarlc;      // File address of relocation table
            public UInt16 e_ovno;    // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res1;    // Reserved words
            public UInt16 e_oemid;       // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;     // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2;    // Reserved words
            public Int32 e_lfanew;      // File address of new exe header
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }



        public enum MachineType : ushort
        {
            /// <summary>
            /// The content of this field is assumed to be applicable to any machine type
            /// </summary>
            Unknown = 0x0000,
            /// <summary>
            /// Intel 386 or later processors and compatible processors
            /// </summary>
            I386 = 0x014c,
            R3000 = 0x0162,
            /// <summary>
            ///  MIPS little endian
            /// </summary>
            R4000 = 0x0166,
            R10000 = 0x0168,
            /// <summary>
            /// MIPS little-endian WCE v2
            /// </summary>
            WCEMIPSV2 = 0x0169,
            /// <summary>
            /// Alpha AXP
            /// </summary>
            Alpha = 0x0184,
            /// <summary>
            /// Hitachi SH3
            /// </summary>
            SH3 = 0x01a2,
            /// <summary>
            /// Hitachi SH3 DSP
            /// </summary>
            SH3DSP = 0x01a3,
            /// <summary>
            /// Hitachi SH4
            /// </summary>
            SH4 = 0x01a6,
            /// <summary>
            /// Hitachi SH5
            /// </summary>
            SH5 = 0x01a8,
            /// <summary>
            /// ARM little endian
            /// </summary>
            ARM = 0x01c0,
            /// <summary>
            /// Thumb
            /// </summary>
            Thumb = 0x01c2,
            /// <summary>
            /// ARM Thumb-2 little endian
            /// </summary>
            ARMNT = 0x01c4,
            /// <summary>
            /// Matsushita AM33
            /// </summary>
            AM33 = 0x01d3,
            /// <summary>
            /// Power PC little endian
            /// </summary>
            PowerPC = 0x01f0,
            /// <summary>
            /// Power PC with floating point support
            /// </summary>
            PowerPCFP = 0x01f1,
            /// <summary>
            /// Intel Itanium processor family
            /// </summary>
            IA64 = 0x0200,
            /// <summary>
            /// MIPS16
            /// </summary>
            MIPS16 = 0x0266,
            /// <summary>
            /// Motorola 68000 series
            /// </summary>
            M68K = 0x0268,
            /// <summary>
            /// Alpha AXP 64-bit
            /// </summary>
            Alpha64 = 0x0284,
            /// <summary>
            /// MIPS with FPU
            /// </summary>
            MIPSFPU = 0x0366,
            /// <summary>
            /// MIPS16 with FPU
            /// </summary>
            MIPSFPU16 = 0x0466,
            /// <summary>
            /// EFI byte code
            /// </summary>
            EBC = 0x0ebc,
            /// <summary>
            /// RISC-V 32-bit address space
            /// </summary>
            RISCV32 = 0x5032,
            /// <summary>
            /// RISC-V 64-bit address space
            /// </summary>
            RISCV64 = 0x5064,
            /// <summary>
            /// RISC-V 128-bit address space
            /// </summary>
            RISCV128 = 0x5128,
            /// <summary>
            /// x64
            /// </summary>
            AMD64 = 0x8664,
            /// <summary>
            /// ARM64 little endian
            /// </summary>
            ARM64 = 0xaa64,
            /// <summary>
            /// LoongArch 32-bit processor family
            /// </summary>
            LoongArch32 = 0x6232,
            /// <summary>
            /// LoongArch 64-bit processor family
            /// </summary>
            LoongArch64 = 0x6264,
            /// <summary>
            /// Mitsubishi M32R little endian
            /// </summary>
            M32R = 0x9041
        }
        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }
        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14

        }
        public enum DllCharacteristicsType : ushort
        {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }


        [StructLayout(LayoutKind.Explicit)]
        public unsafe struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;
            [FieldOffset(8)] public UInt32 VirtualSize;
            [FieldOffset(12)] public UInt32 VirtualAddress;
            [FieldOffset(16)] public UInt32 SizeOfRawData;
            [FieldOffset(20)] public UInt32 PointerToRawData;
            [FieldOffset(24)] public UInt32 PointerToRelocations;
            [FieldOffset(28)] public UInt32 PointerToLinenumbers;
            [FieldOffset(32)] public UInt16 NumberOfRelocations;
            [FieldOffset(34)] public UInt16 NumberOfLinenumbers;
            [FieldOffset(36)] public UInt32 Characteristics;
            public string Section
            {

                get { return new string(Name); }
            }

        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            // PE32 contains this additional field
            [FieldOffset(24)]
            public uint BaseOfData;

            [FieldOffset(28)]
            public uint ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public uint SizeOfStackReserve;

            [FieldOffset(76)]
            public uint SizeOfStackCommit;

            [FieldOffset(80)]
            public uint SizeOfHeapReserve;

            [FieldOffset(84)]
            public uint SizeOfHeapCommit;

            [FieldOffset(88)]
            public uint LoaderFlags;

            [FieldOffset(92)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(96)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(104)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_NT_HEADERS32
        {
            [FieldOffset(0)]
            public UInt32 Signature;

            [FieldOffset(4)]
            public IMAGE_FILE_HEADER FileHeader;

            [FieldOffset(24)]
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader;




        }


        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_IMPORT_DESCRIPTOR
        {
            [FieldOffset(0)]
            public uint Characteristics;

            [FieldOffset(0)]
            public uint OriginalFirstThunk;

            [FieldOffset(4)]
            public uint TimeDateStamp;

            [FieldOffset(8)]
            public uint ForwarderChain;

            [FieldOffset(12)]
            public uint Name;

            [FieldOffset(16)]
            public uint FirstThunk;
        }


        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_THUNK_DATA32
        {
            [FieldOffset(0)]
            public uint ForwarderString;

            [FieldOffset(0)]
            public uint Function;

            [FieldOffset(0)]
            public uint Ordinal;

            [FieldOffset(0)]
            public uint AddressOfData;
        }


        [StructLayout(LayoutKind.Sequential)]
        public  struct IMAGE_IMPORT_BY_NAME
        {
            
            public UInt16 Hint;
            public char Name;

        }


        [DllImport("Kernel32.dll")]
        public static extern int GetLastError();

       


        [DllImport("Kernel32.dll")]
        public static extern void CopyMemory(
            IntPtr destination,
            IntPtr source,
            int size
            );


        [DllImport("Kernel32.dll")]
        public static extern bool UnmapViewOfFile(IntPtr address);


        [DllImport("Kernel32.dll")]
        public static extern IntPtr MapViewOfFile(
            IntPtr hFileMappingObject,
            UInt32 dwDesiredAccess,
            UInt32 dwFileOffsetHigh,
            UInt32 dwFileOffsetLow,
            int dwNumberOfBytesToMap
            );


        [DllImport("Kernel32.dll")]
        public static extern IntPtr OpenFileMappingA(
            UInt32 dwDesiredAccess,
            [param:MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
            string lpName
            );

        [DllImport("Kernel32.dll")]
        public static extern IntPtr CreateFileMappingA(
            IntPtr filehandle,
            IntPtr lpFileMappingAttributes,
            UInt32 flProtect,
            UInt32 dwMaximumSizeHigh,
            UInt32 dwMaximumSizeLow,
            string lpName
            );


        [DllImport("Kernel32.dll")]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            int dwSize,
            UInt32 flAllocationType,
            UInt32 flProtect
            );


        [DllImport("Kernel32.dll")]
        public static extern bool VirtualFree(
            IntPtr lpAddress,
            int dwSize,
            UInt32 dwFreeType
            );

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);

        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetProcAddress(
            IntPtr handle,
            string functionname
            );

        [DllImport("Kernel32.dll")]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32", CharSet = CharSet.Ansi)]
        public static extern IntPtr CreateThread(
            IntPtr lpThreadAttributes,
            uint dwStackSize, 
            IntPtr lpStartAddress,
            IntPtr lpParameter, 
            uint dwCreationFlags,
            ref uint lpThreadId);

        public static string CheckBitVersion(string filepath)
        {
            string bit32 = "32bit";
            string bit64 = "64bit";

            FileStream fs = File.OpenRead(filepath);
            BinaryReader br = new BinaryReader(fs);
            byte[] dos = new byte[Marshal.SizeOf(typeof(IMAGE_DOS_HEADER))];
            br.BaseStream.Read(dos, 0, Marshal.SizeOf(typeof(IMAGE_DOS_HEADER)));
            byte[] lfanew = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                //Console.WriteLine(  dos[60 + i].ToString("X"));
                lfanew[i] = dos[60 + i];
            }

            int peheaderoffset = BitConverter.ToInt32(lfanew, 0);
            br.BaseStream.Seek(peheaderoffset + 4 + 20, SeekOrigin.Begin);
            
            byte[] bitversion = new byte[2];
            br.BaseStream.Read(bitversion, 0, 2);

            br.Close();
            fs.Close();
            string value = BitConverter.ToString(bitversion);
            if (value == "0B-01")
            {
                return bit32;
            }
            else if (value == "0B-02")
            {
                return bit64;
            }
            return bit32;

        }


        public static void Main(string[] args)
        {
            /*#define FILE_MAP_ALL_ACCESS     0xf001f
                 #define FILE_MAP_READ   4
                 #define FILE_MAP_WRITE  2
                 #define FILE_MAP_COPY   1*/

            //string exe_path = @"D:\red teaming tools\dumpusers.exe";
            string exe_path = @"D:\red teaming tools\CFF_Explorer\a.exe";
            //string exe_path = @"C:\Program Files (x86)\VideoLAN\VLC\vlc.exe";
            
            string bit = CheckBitVersion(exe_path);
            Console.WriteLine(bit);

            if (bit != "32bit")
            {
                Environment.Exit(0);
            }

            byte[] rawfile = File.ReadAllBytes(exe_path);

            FileStream fs = File.OpenRead(exe_path);
            BinaryReader br = new BinaryReader(fs);


            

            byte[] dos = new byte[64];
            br.BaseStream.Read(dos, 0, Marshal.SizeOf(typeof(IMAGE_DOS_HEADER)));

            byte[] lfanew = new byte[4];
            for(int i = 0; i < 4; i++)
            {
                //Console.WriteLine(  dos[60 + i].ToString("X"));
                lfanew[i] = dos[60 + i];
            }

            Console.WriteLine(BitConverter.ToString(lfanew));
            
            // 64 position
            Console.WriteLine("brrrr position: {0}",br.BaseStream.Position);
            
            int peheaderoffset = BitConverter.ToInt32(lfanew,0);

            byte[] sizeofimage = new byte[4];
            br.BaseStream.Position = peheaderoffset + 80;
            br.BaseStream.Read(sizeofimage, 0, 4);
            br.BaseStream.Position = 0;

            int imagesize = BitConverter.ToInt32(sizeofimage, 0);
            Console.WriteLine("size of image: {0}", imagesize.ToString("X"));


            IMAGE_NT_HEADERS32 ntheader = new IMAGE_NT_HEADERS32();

            
           IntPtr baseaddress=  VirtualAlloc(IntPtr.Zero,imagesize, 0x00001000, 0x40);

            


            if (baseaddress != IntPtr.Zero)
            {
                Console.WriteLine("Memory allocated at {0}", baseaddress.ToString("X"));

                br.BaseStream.Position = 0;
                byte[] temp = new byte[peheaderoffset];
                br.BaseStream.Read(temp, 0, peheaderoffset);
                Marshal.Copy(temp, 0, baseaddress, peheaderoffset);

                IMAGE_DOS_HEADER dosheader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(baseaddress, typeof(IMAGE_DOS_HEADER));

                Console.WriteLine("Magic bytes: {0}", new string(dosheader.e_magic));
                Console.WriteLine("PE Header offset from base: {0}", dosheader.e_lfanew.ToString("X"));


                byte[] signature = new byte[4];
                br.BaseStream.Position = peheaderoffset;
                br.BaseStream.Read(signature, 0, 4);

                Marshal.Copy(signature, 0, baseaddress + peheaderoffset, signature.Length);

                ntheader.Signature = (uint)Marshal.ReadInt32(baseaddress + peheaderoffset);

                Console.WriteLine(ntheader.Signature.ToString("X"));
                if (ntheader.Signature.ToString("X") == "4550")
                {
                    Console.WriteLine("Valid PE File");
                }
                else
                {
                    Environment.Exit(0);
                }



                byte[] filehdr = new byte[Marshal.SizeOf(typeof(IMAGE_FILE_HEADER))];
                br.BaseStream.Read(filehdr, 0, filehdr.Length);

                Marshal.Copy(filehdr, 0, baseaddress + peheaderoffset + 4, filehdr.Length);

                ntheader.FileHeader = (IMAGE_FILE_HEADER)Marshal.PtrToStructure(baseaddress + peheaderoffset + 4, typeof(IMAGE_FILE_HEADER));

                Console.WriteLine("Machine: {0}", ntheader.FileHeader.Machine.ToString("X"));
                Console.WriteLine("Number of sections: {0}", ntheader.FileHeader.NumberOfSections);
                Console.WriteLine("Size of Optional Header: {0}", ntheader.FileHeader.SizeOfOptionalHeader);



                byte[] optionalhdr = new byte[ntheader.FileHeader.SizeOfOptionalHeader];
                br.BaseStream.Read(optionalhdr, 0, ntheader.FileHeader.SizeOfOptionalHeader);



                Marshal.Copy(optionalhdr, 0, baseaddress + peheaderoffset + 24, ntheader.FileHeader.SizeOfOptionalHeader);


                ntheader.OptionalHeader = (IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure(baseaddress + peheaderoffset + 24, typeof(IMAGE_OPTIONAL_HEADER32));

                Console.WriteLine("Magic: {0}", ntheader.OptionalHeader.Magic.ToString("X"));
                Console.WriteLine("Address of EntryPoint: {0}", ntheader.OptionalHeader.AddressOfEntryPoint.ToString("X"));
                Console.WriteLine("Size of optional header: {0}", ntheader.OptionalHeader.SizeOfImage.ToString("X"));

                IntPtr entrypoint = (IntPtr)ntheader.OptionalHeader.AddressOfEntryPoint;
                Console.WriteLine(entrypoint.ToString("X"));

                Console.WriteLine("Import directory");
                Console.WriteLine(ntheader.OptionalHeader.ImportTable.VirtualAddress.ToString("X"));
                Console.WriteLine(ntheader.OptionalHeader.ImportTable.Size);

                Console.WriteLine("Import Address Table");
                Console.WriteLine(ntheader.OptionalHeader.IAT.VirtualAddress.ToString("X"));
                Console.WriteLine(ntheader.OptionalHeader.IAT.Size);

                IMAGE_SECTION_HEADER[] sh = new IMAGE_SECTION_HEADER[ntheader.FileHeader.NumberOfSections];

                for (int i = 0; i < ntheader.FileHeader.NumberOfSections; i++)
                {

                    byte[] sectionhdr = new byte[Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))];
                    br.BaseStream.Read(sectionhdr, 0, Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)));

                    Marshal.Copy(sectionhdr, 0, (baseaddress + peheaderoffset + 24 + ntheader.FileHeader.SizeOfOptionalHeader) + (i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))),sectionhdr.Length);

                    sh[i] =(IMAGE_SECTION_HEADER) Marshal.PtrToStructure((baseaddress + peheaderoffset + 24 + ntheader.FileHeader.SizeOfOptionalHeader) + (i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))), typeof(IMAGE_SECTION_HEADER));

                    
                   // Mapping sections into memory
                        byte[] temp2 = new byte[sh[i].VirtualSize];
                        for (int j = 0; j < temp2.Length; j++)
                        {
                            temp2[j] = rawfile[sh[i].PointerToRawData + j];
                            //Console.Write(temp2[j].ToString("X") + ",");
                            

                        }
                        Marshal.Copy(temp2, 0, baseaddress + (int)sh[i].VirtualAddress, temp2.Length);
                    

                    

                    Console.WriteLine(rawfile[sh[i].PointerToRawData].ToString("X"));
                    Console.WriteLine("Section Name: {0}",new string(sh[i].Name));
                    Console.WriteLine("Virtual size: {0}", sh[i].VirtualSize.ToString("X"));
                    Console.WriteLine("Virtual Address: {0}",sh[i].VirtualAddress.ToString("X"));
                    Console.WriteLine("Size of raw data: {0}",sh[i].SizeOfRawData);
                    Console.WriteLine("Pointer to raw data: {0}",sh[i].PointerToRawData.ToString("X"));
                    Console.WriteLine("Characteristics: {0}",sh[i].Characteristics.ToString("X")    );
                }
                Console.WriteLine(ntheader.OptionalHeader.SizeOfHeaders);
                Console.WriteLine(rawfile.Length);
                //byte[] remaining = new byte[imagesize - (int)ntheader.OptionalHeader.SizeOfHeaders];
                // br.BaseStream.Read(remaining, 0, remaining.Length);

                // Marshal.Copy(remaining, 0, baseaddress + peheaderoffset + 24 + ntheader.FileHeader.SizeOfOptionalHeader + (ntheader.FileHeader.NumberOfSections * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))),remaining.Length);

                Console.WriteLine(ntheader.OptionalHeader.ImportTable.VirtualAddress.ToString("X"));
                IntPtr firstimport = (IntPtr)baseaddress + (int)ntheader.OptionalHeader.ImportTable.VirtualAddress;

                
                IMAGE_IMPORT_DESCRIPTOR imp1 = (IMAGE_IMPORT_DESCRIPTOR) Marshal.PtrToStructure(firstimport, typeof(IMAGE_IMPORT_DESCRIPTOR));

                while (imp1.Name != 0)
                {
                    
                    string dllname = Marshal.PtrToStringAnsi(baseaddress + (int)imp1.Name);
                    //Console.WriteLine(dllname);


                    IntPtr dllhandle = LoadLibrary(dllname);
                    //Console.WriteLine("last error: {0}",GetLastError());

                    IntPtr originalfirstthunk = baseaddress + (int)imp1.OriginalFirstThunk;
                    Console.WriteLine("OriginalFirst thunk: {0}",originalfirstthunk.ToString("X"));


                    IntPtr firstthunk = baseaddress + (int)imp1.FirstThunk;
                    Console.WriteLine("First Thunk: {0}",firstthunk.ToString("X"));
                    

                    IMAGE_THUNK_DATA32 thunk1 = (IMAGE_THUNK_DATA32)Marshal.PtrToStructure(originalfirstthunk, typeof(IMAGE_THUNK_DATA32));

                    int count = 0;
                    while ((int)thunk1.Function != 0)
                    {
                        IntPtr name1 = baseaddress + (int)thunk1.Function;
                        Console.WriteLine(thunk1.Function.ToString("X"));

                        IMAGE_IMPORT_BY_NAME function1 = (IMAGE_IMPORT_BY_NAME)Marshal.PtrToStructure(name1, typeof(IMAGE_IMPORT_BY_NAME));

                        string firstfunction = Marshal.PtrToStringAnsi(name1 + 2);

                        Console.WriteLine(firstfunction);

                        // writing function addresses to first thunk 

                        IntPtr functionaddress = GetProcAddress(dllhandle, firstfunction);
                        Console.WriteLine(GetLastError());
                        Console.WriteLine("Functionptr: {0}",functionaddress.ToString("X"));
                        string address = functionaddress.ToInt32().ToString("X");


                        // byte[] functionaddr= Encoding.ASCII.GetBytes(functionaddress.ToInt32().ToString("X"));

                        Console.WriteLine("First Thunk: {0}",firstthunk.ToString("X"));

                        Marshal.WriteInt32(firstthunk, functionaddress.ToInt32());

                        firstthunk += 4;

                        //Console.WriteLine("Function adr value: {0}",BitConverter.ToString(functionaddr));
                        
                        originalfirstthunk += Marshal.SizeOf(typeof(IMAGE_THUNK_DATA32));
                        thunk1 = (IMAGE_THUNK_DATA32)Marshal.PtrToStructure(originalfirstthunk, typeof(IMAGE_THUNK_DATA32));
                        count += 1;

                       
                    }

                    FreeLibrary(dllhandle);

                    Console.WriteLine("Number of imported functions: {0}",count);
                    // Console.WriteLine(Marshal.PtrToStringAnsi(name1 + 2+firstfunction.Length+4));

                    firstimport += Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR));
                    imp1 = (IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(firstimport, typeof(IMAGE_IMPORT_DESCRIPTOR));


                }
                Console.WriteLine(entrypoint.ToString("X"));
                IntPtr threadhandle = IntPtr.Zero;
                uint threadid = 0;
                threadhandle = CreateThread(IntPtr.Zero,
                    0,
                   baseaddress+(int) entrypoint,
                   IntPtr.Zero,
                   0,
                   ref threadid
                    );
                Console.WriteLine(GetLastError());
                VirtualFree(baseaddress, 0, 0x00008000);

            }

           

            Console.ReadKey();
        }
    }
}
