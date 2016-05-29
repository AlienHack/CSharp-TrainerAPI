using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace XenoCoreZ_Trainer_API
{
    internal class MemoryApi
    {
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [DllImport("User32.dll")]
        public static extern int FindWindow(string lpClassName, string lpWindowName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] buffer, uint size, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        //*********** CUSTOM

        public static IntPtr GetBaseModule(uint pid, string moduleName)
        {
            Process p = Process.GetProcessById((int)pid);
            foreach (ProcessModule pm in p.Modules)
            {
                if (String.CompareOrdinal(pm.ModuleName, moduleName) == 0)
                {
                    return pm.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }

        public static IntPtr GetAddressPointer(IntPtr hProcess, IntPtr baseAddress, int[] offsets)
        {
            IntPtr tempAddress = baseAddress;
            foreach (int myOffset in offsets)
            {
                tempAddress = (IntPtr)(ReadInt(hProcess, tempAddress) + myOffset);
            }
            return tempAddress;
        }

        public static bool WriteByteArray(IntPtr hProcess, IntPtr baseAddress, byte[] newVal)
        {
            bool returnVal;

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(hProcess, baseAddress, (UIntPtr)newVal.Length, 0x40, out oldProtect); //0x40 = page execute read write
            returnVal = WriteProcessMemory(hProcess, baseAddress, newVal, newVal.Length, out numWrite);
            VirtualProtectEx(hProcess, baseAddress, (UIntPtr)newVal.Length, oldProtect, out oldProtect);

            return returnVal;
        }

        public static bool WriteInt(IntPtr hProcess, IntPtr baseAddress, int val)
        {
            bool returnVal;

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(hProcess, baseAddress, (UIntPtr)sizeof(int), 0x40, out oldProtect); //0x40 = page execute read write
            returnVal = WriteProcessMemory(hProcess, baseAddress, BitConverter.GetBytes(val), sizeof(int), out numWrite);
            VirtualProtectEx(hProcess, baseAddress, (UIntPtr)sizeof(int), oldProtect, out oldProtect);

            return returnVal;
        }

        public static bool WriteDouble(IntPtr hProcess, IntPtr baseAddress, double val)
        {
            bool returnVal;

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(hProcess, baseAddress, (UIntPtr)sizeof(double), 0x40, out oldProtect); //0x40 = page execute read write
            returnVal = WriteProcessMemory(hProcess, baseAddress, BitConverter.GetBytes(val), sizeof(double), out numWrite);
            VirtualProtectEx(hProcess, baseAddress, (UIntPtr)sizeof(double), oldProtect, out oldProtect);

            return returnVal;
        }

        public static bool WriteFloat(IntPtr hProcess, IntPtr baseAddress, float val)
        {
            bool returnVal;

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(hProcess, baseAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            returnVal = WriteProcessMemory(hProcess, baseAddress, BitConverter.GetBytes(val), sizeof(float), out numWrite);
            VirtualProtectEx(hProcess, baseAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return returnVal;
        }

        public static bool WriteStringA(IntPtr hProcess, IntPtr baseAddress, string val)
        {
            bool returnVal;

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(hProcess, baseAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            returnVal = WriteProcessMemory(hProcess, baseAddress, Encoding.ASCII.GetBytes(val), Encoding.ASCII.GetBytes(val).Length, out numWrite);
            VirtualProtectEx(hProcess, baseAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return returnVal;
        }

        public static bool WriteStringW(IntPtr hProcess, IntPtr baseAddress, string val)
        {
            bool returnVal;

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(hProcess, baseAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            returnVal = WriteProcessMemory(hProcess, baseAddress, Encoding.Unicode.GetBytes(val), Encoding.Unicode.GetBytes(val).Length, out numWrite);
            VirtualProtectEx(hProcess, baseAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return returnVal;
        }

        public static int ReadInt(IntPtr hProcess, IntPtr baseAddress)
        {
            byte[] buffer = new byte[sizeof(int)];
            IntPtr numRead;
            uint oldProtect;
            VirtualProtectEx(hProcess, baseAddress, (UIntPtr)sizeof(int), 0x40, out oldProtect); //0x40 = page execute read write
            ReadProcessMemory(hProcess, baseAddress, buffer, sizeof(int), out numRead);
            VirtualProtectEx(hProcess, baseAddress, (UIntPtr)sizeof(int), oldProtect, out oldProtect);

            return BitConverter.ToInt32(buffer, 0);
        }

        public static double ReadDouble(IntPtr hProcess, IntPtr baseAddress)
        {
            byte[] buffer = new byte[sizeof(double)];
            IntPtr numRead;
            uint oldProtect;
            VirtualProtectEx(hProcess, baseAddress, (UIntPtr)sizeof(double), 0x40, out oldProtect); //0x40 = page execute read write
            ReadProcessMemory(hProcess, baseAddress, buffer, sizeof(double), out numRead);
            VirtualProtectEx(hProcess, baseAddress, (UIntPtr)sizeof(double), oldProtect, out oldProtect);

            return BitConverter.ToDouble(buffer, 0);
        }

        public static float ReadFloat(IntPtr hProcess, IntPtr baseAddress)
        {
            byte[] buffer = new byte[sizeof(float)];
            IntPtr numRead;
            uint oldProtect;
            VirtualProtectEx(hProcess, baseAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            ReadProcessMemory(hProcess, baseAddress, buffer, sizeof(float), out numRead);
            VirtualProtectEx(hProcess, baseAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return BitConverter.ToSingle(buffer, 0);
        }

        public static byte[] ReadBytes(IntPtr hProcess, IntPtr baseAddress, int size)
        {
            byte[] buffer = new byte[size];
            IntPtr numRead;
            uint oldProtect;
            VirtualProtectEx(hProcess, baseAddress, (UIntPtr)size, 0x40, out oldProtect); //0x40 = page execute read write
            ReadProcessMemory(hProcess, baseAddress, buffer, (uint)size, out numRead);
            VirtualProtectEx(hProcess, baseAddress, (UIntPtr)size, oldProtect, out oldProtect);

            return buffer;
        }
    }
}