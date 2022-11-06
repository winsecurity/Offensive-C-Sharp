using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace api_hooking
{
    partial class Program
    {
        
        public delegate void msg(IntPtr p1, string h, string l, int i);








        public static IntPtr funcaddress;
        public static byte[] savedbytes = new byte[5];

        public static void hookedfunc(IntPtr p1,string h,string l,int i)
        {

            Marshal.Copy(savedbytes, 0, funcaddress, 5);



            msg m1 = (msg)Marshal.GetDelegateForFunctionPointer(funcaddress, typeof(msg));

            if (h == "process")
            {
                m1(p1, "process hacked", l, i);

            }
            else
            {
                m1(p1,h, l, i);
            }
          //  System.Windows.Forms.MessageBox.Show("hacked");



        }

        public static void hookMsg(IntPtr funcaddress, byte[] saved)
        {
            Marshal.Copy(saved, 0, funcaddress, saved.Length);

            Delegate m = Marshal.GetDelegateForFunctionPointer(funcaddress, typeof(msg));
            m.DynamicInvoke(IntPtr.Zero, "hi", "hello", 0);

        }




        static void Main(string[] args)
        {

            IntPtr user32handle = LoadLibrary("User32.dll");
              funcaddress = GetProcAddress(user32handle, "MessageBoxA");

             savedbytes = new byte[5];
            Marshal.Copy(funcaddress, savedbytes, 0, savedbytes.Length);

            byte[] jump = new byte[5];
            jump[0] = 0xe9;


            IntPtr  hookedaddress =Marshal.GetFunctionPointerForDelegate((msg)hookedfunc);

            int jumpoffset = (int)hookedaddress - 5 - (int)funcaddress;
            Array.Copy(BitConverter.GetBytes(jumpoffset),0,jump,1,4);

            uint old = 0;
            VirtualProtect(funcaddress, 5, 0x40, out old);

            Marshal.Copy(jump, 0, funcaddress, 5);


            msg m =(msg)Marshal.GetDelegateForFunctionPointer(funcaddress, typeof(msg));
            
            
            m(IntPtr.Zero, "process", "really legit", 0);

        }


    }
}
