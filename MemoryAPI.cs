using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace XenoCoreZ_Trainer_API
{
    internal class MemoryAPI
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
        public static extern Int32 FindWindow(String lpClassName, String lpWindowName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Int32 ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] buffer, UInt32 size, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        //*********** CUSTOM

        public static IntPtr GetBaseModule(uint PID, string ModuleName)
        {
            Process P = Process.GetProcessById((int)PID);
            if (P != null)
            {
                foreach (ProcessModule pm in P.Modules)
                {
                    if (String.Compare(pm.ModuleName, ModuleName) == 0)
                    {
                        return pm.BaseAddress;
                    }
                }
            }
            return IntPtr.Zero;
        }

        public static IntPtr GetAddressPointer(IntPtr hProcess, IntPtr BaseAddress, int[] offsets)
        {
            IntPtr TempAddress = BaseAddress;
            foreach (int myOffset in offsets)
            {
                TempAddress = (IntPtr)(ReadInt(hProcess, TempAddress) + myOffset);
            }
            return TempAddress;
        }

        public static bool WriteByteArray(IntPtr hProcess, IntPtr BaseAddress, byte[] NewVal)
        {
            bool ReturnVal;

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)NewVal.Length, 0x40, out oldProtect); //0x40 = page execute read write
            ReturnVal = WriteProcessMemory(hProcess, BaseAddress, NewVal, NewVal.Length, out numWrite);
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)NewVal.Length, oldProtect, out oldProtect);

            return ReturnVal;
        }

        public static bool WriteInt(IntPtr hProcess, IntPtr BaseAddress, int Val)
        {
            bool ReturnVal;

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(int), 0x40, out oldProtect); //0x40 = page execute read write
            ReturnVal = WriteProcessMemory(hProcess, BaseAddress, BitConverter.GetBytes(Val), sizeof(int), out numWrite);
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(int), oldProtect, out oldProtect);

            return ReturnVal;
        }

        public static bool WriteDouble(IntPtr hProcess, IntPtr BaseAddress, double Val)
        {
            bool ReturnVal;

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(double), 0x40, out oldProtect); //0x40 = page execute read write
            ReturnVal = WriteProcessMemory(hProcess, BaseAddress, BitConverter.GetBytes(Val), sizeof(double), out numWrite);
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(double), oldProtect, out oldProtect);

            return ReturnVal;
        }

        public static bool WriteFloat(IntPtr hProcess, IntPtr BaseAddress, float Val)
        {
            bool ReturnVal;

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            ReturnVal = WriteProcessMemory(hProcess, BaseAddress, BitConverter.GetBytes(Val), sizeof(float), out numWrite);
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return ReturnVal;
        }

        public static bool WriteStringA(IntPtr hProcess, IntPtr BaseAddress, string Val)
        {
            bool ReturnVal;

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            ReturnVal = WriteProcessMemory(hProcess, BaseAddress, Encoding.ASCII.GetBytes(Val), Encoding.ASCII.GetBytes(Val).Length, out numWrite);
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return ReturnVal;
        }

        public static bool WriteStringW(IntPtr hProcess, IntPtr BaseAddress, string Val)
        {
            bool ReturnVal;

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            ReturnVal = WriteProcessMemory(hProcess, BaseAddress, Encoding.Unicode.GetBytes(Val), Encoding.Unicode.GetBytes(Val).Length, out numWrite);
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return ReturnVal;
        }

        public static int ReadInt(IntPtr hProcess, IntPtr BaseAddress)
        {
            byte[] buffer = new byte[sizeof(int)];
            IntPtr numRead;
            uint oldProtect;
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(int), 0x40, out oldProtect); //0x40 = page execute read write
            int result = ReadProcessMemory(hProcess, BaseAddress, buffer, sizeof(int), out numRead);
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(int), oldProtect, out oldProtect);

            return BitConverter.ToInt32(buffer, 0);
        }

        public static double ReadDouble(IntPtr hProcess, IntPtr BaseAddress)
        {
            byte[] buffer = new byte[sizeof(double)];
            IntPtr numRead;
            uint oldProtect;
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(double), 0x40, out oldProtect); //0x40 = page execute read write
            double result = ReadProcessMemory(hProcess, BaseAddress, buffer, sizeof(double), out numRead);
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(double), oldProtect, out oldProtect);

            return BitConverter.ToDouble(buffer, 0);
        }

        public static float ReadFloat(IntPtr hProcess, IntPtr BaseAddress)
        {
            byte[] buffer = new byte[sizeof(float)];
            IntPtr numRead;
            uint oldProtect;
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            float result = ReadProcessMemory(hProcess, BaseAddress, buffer, sizeof(float), out numRead);
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return BitConverter.ToSingle(buffer, 0);
        }

        public static byte[] ReadBytes(IntPtr hProcess, IntPtr BaseAddress, int Size)
        {
            byte[] buffer = new byte[Size];
            IntPtr numRead;
            uint oldProtect;
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)Size, 0x40, out oldProtect); //0x40 = page execute read write
            float result = ReadProcessMemory(hProcess, BaseAddress, buffer, (uint)Size, out numRead);
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)Size, oldProtect, out oldProtect);

            return buffer;
        }
    }
}