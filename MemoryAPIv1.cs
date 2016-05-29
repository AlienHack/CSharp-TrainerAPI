using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace XenoCoreZ_Trainer_API
{
    internal class MemoryAPIv1
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

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public uint RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        private List<MEMORY_BASIC_INFORMATION> MemoryRegion { get; set; }

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

        [DllImport("kernel32.dll")]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

        private void MemInfo(IntPtr pHandle)
        {
            IntPtr Addy = new IntPtr();
            while (true)
            {
                MEMORY_BASIC_INFORMATION MemInfo = new MEMORY_BASIC_INFORMATION();
                int MemDump = VirtualQueryEx(pHandle, Addy, out MemInfo, Marshal.SizeOf(MemInfo));
                if (MemDump == 0) break;
                if ((MemInfo.State & 0x1000) != 0 && (MemInfo.Protect & 0x100) == 0)
                    MemoryRegion.Add(MemInfo);
                Addy = new IntPtr(MemInfo.BaseAddress.ToInt32() + (int)MemInfo.RegionSize);
            }
        }

        private IntPtr Scan(byte[] sIn, byte[] sFor)
        {
            int[] sBytes = new int[256]; int Pool = 0;
            int End = sFor.Length - 1;
            for (int i = 0; i < 256; i++)
                sBytes[i] = sFor.Length;
            for (int i = 0; i < End; i++)
                sBytes[sFor[i]] = End - i;
            while (Pool <= sIn.Length - sFor.Length)
            {
                for (int i = End; sIn[Pool + i] == sFor[i]; i--)
                    if (i == 0) return new IntPtr(Pool);
                Pool += sBytes[sIn[Pool + End]];
            }
            return IntPtr.Zero;
        }

        private bool isValid()
        {
            if (hProcess == IntPtr.Zero)
            {
                return false;
            }
            return true;
        }

        //Required Variable
        private static uint PID = 0;

        private static int WindowHandle = 0;
        private static IntPtr hProcess = IntPtr.Zero;
        private static string PGameWindowTitle;
        private static string PGameExecutable;
        private static string PModuleName;

        //Constructor
        public MemoryAPIv1(string GameWindowTitle, string GameExecutable, string ModuleName)
        {
            PGameWindowTitle = GameWindowTitle;
            PGameExecutable = GameExecutable;
            PModuleName = ModuleName;

            //Predefined Initializing
            WindowHandle = FindWindow(null, GameWindowTitle);

            if (WindowHandle == 0)
            {
                foreach (Process P in Process.GetProcessesByName(GameExecutable))
                {
                    PID = (uint)P.Id;
                    break;
                }
                if (PID == 0)
                {
                    MessageBox.Show("Game not found...\n\nReason: PID=0");
                    return;
                }
            }
            else
            {
                GetWindowThreadProcessId((IntPtr)WindowHandle, out PID);
            }
            hProcess = GetBaseModule(ModuleName);

            if (hProcess == IntPtr.Zero)
            {
                MessageBox.Show("Cant get process handle...\n\nReason: hProcess=0");
            }
        }

        //Functions
        public IntPtr GetBaseModule(string ModuleName)
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

        public IntPtr GetBaseModule()
        {
            Process P = Process.GetProcessById((int)PID);
            if (P != null)
            {
                foreach (ProcessModule pm in P.Modules)
                {
                    if (String.Compare(pm.ModuleName, PModuleName) == 0)
                    {
                        return pm.BaseAddress;
                    }
                }
            }
            return IntPtr.Zero;
        }

        public IntPtr GetAddressPointer(IntPtr BaseAddress, int[] offsets)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return IntPtr.Zero;
            }
            IntPtr TempAddress = BaseAddress;
            foreach (int myOffset in offsets)
            {
                TempAddress = (IntPtr)(ReadInt(TempAddress) + myOffset);
            }
            return TempAddress;
        }

        public bool WriteByteArray(IntPtr BaseAddress, byte[] NewVal)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            bool ReturnVal;

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)NewVal.Length, 0x40, out oldProtect); //0x40 = page execute read write
            ReturnVal = WriteProcessMemory(hProcess, BaseAddress, NewVal, NewVal.Length, out numWrite);
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)NewVal.Length, oldProtect, out oldProtect);

            return ReturnVal;
        }

        public bool WriteByteArrayPointer(IntPtr BaseAddress, int[] OffsetAddress, byte[] NewVal)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            bool ReturnVal;

            IntPtr numWrite;
            uint oldProtect;

            IntPtr ActualAddress = GetAddressPointer(BaseAddress, OffsetAddress);

            VirtualProtectEx(hProcess, ActualAddress, (UIntPtr)NewVal.Length, 0x40, out oldProtect); //0x40 = page execute read write
            ReturnVal = WriteProcessMemory(hProcess, ActualAddress, NewVal, NewVal.Length, out numWrite);
            VirtualProtectEx(hProcess, ActualAddress, (UIntPtr)NewVal.Length, oldProtect, out oldProtect);

            return ReturnVal;
        }

        public bool WriteInt(IntPtr BaseAddress, int Val)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            bool ReturnVal;

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(int), 0x40, out oldProtect); //0x40 = page execute read write
            ReturnVal = WriteProcessMemory(hProcess, BaseAddress, BitConverter.GetBytes(Val), sizeof(int), out numWrite);
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(int), oldProtect, out oldProtect);

            return ReturnVal;
        }

        public bool WriteIntPointer(IntPtr BaseAddress, int[] OffsetAddress, int Val)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            bool ReturnVal;

            IntPtr numWrite;
            uint oldProtect;

            IntPtr ActualAddress = GetAddressPointer(BaseAddress, OffsetAddress);

            VirtualProtectEx(hProcess, ActualAddress, (UIntPtr)sizeof(int), 0x40, out oldProtect); //0x40 = page execute read write
            ReturnVal = WriteProcessMemory(hProcess, ActualAddress, BitConverter.GetBytes(Val), sizeof(int), out numWrite);
            VirtualProtectEx(hProcess, ActualAddress, (UIntPtr)sizeof(int), oldProtect, out oldProtect);

            return ReturnVal;
        }

        public bool WriteDouble(IntPtr BaseAddress, double Val)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            bool ReturnVal;

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(double), 0x40, out oldProtect); //0x40 = page execute read write
            ReturnVal = WriteProcessMemory(hProcess, BaseAddress, BitConverter.GetBytes(Val), sizeof(double), out numWrite);
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(double), oldProtect, out oldProtect);

            return ReturnVal;
        }

        public bool WriteDoublePointer(IntPtr BaseAddress, int[] OffsetAddress, double Val)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            bool ReturnVal;

            IntPtr numWrite;
            uint oldProtect;

            IntPtr ActualAddress = GetAddressPointer(BaseAddress, OffsetAddress);

            VirtualProtectEx(hProcess, ActualAddress, (UIntPtr)sizeof(double), 0x40, out oldProtect); //0x40 = page execute read write
            ReturnVal = WriteProcessMemory(hProcess, ActualAddress, BitConverter.GetBytes(Val), sizeof(double), out numWrite);
            VirtualProtectEx(hProcess, ActualAddress, (UIntPtr)sizeof(double), oldProtect, out oldProtect);

            return ReturnVal;
        }

        public bool WriteFloat(IntPtr BaseAddress, float Val)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            bool ReturnVal;

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            ReturnVal = WriteProcessMemory(hProcess, BaseAddress, BitConverter.GetBytes(Val), sizeof(float), out numWrite);
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return ReturnVal;
        }

        public bool WriteFloatPointer(IntPtr BaseAddress, int[] OffsetAddress, float Val)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            bool ReturnVal;

            IntPtr numWrite;
            uint oldProtect;

            IntPtr ActualAddress = GetAddressPointer(BaseAddress, OffsetAddress);

            VirtualProtectEx(hProcess, ActualAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            ReturnVal = WriteProcessMemory(hProcess, ActualAddress, BitConverter.GetBytes(Val), sizeof(float), out numWrite);
            VirtualProtectEx(hProcess, ActualAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return ReturnVal;
        }

        public bool WriteStringA(IntPtr BaseAddress, string Val)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            bool ReturnVal;

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            ReturnVal = WriteProcessMemory(hProcess, BaseAddress, Encoding.ASCII.GetBytes(Val), Encoding.ASCII.GetBytes(Val).Length, out numWrite);
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return ReturnVal;
        }

        public bool WriteStringAPointer(IntPtr BaseAddress, int[] OffsetAddress, string Val)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            bool ReturnVal;

            IntPtr numWrite;
            uint oldProtect;

            IntPtr ActualAddress = GetAddressPointer(BaseAddress, OffsetAddress);

            VirtualProtectEx(hProcess, ActualAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            ReturnVal = WriteProcessMemory(hProcess, ActualAddress, Encoding.ASCII.GetBytes(Val), Encoding.ASCII.GetBytes(Val).Length, out numWrite);
            VirtualProtectEx(hProcess, ActualAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return ReturnVal;
        }

        public bool WriteStringW(IntPtr BaseAddress, string Val)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            bool ReturnVal;

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            ReturnVal = WriteProcessMemory(hProcess, BaseAddress, Encoding.Unicode.GetBytes(Val), Encoding.Unicode.GetBytes(Val).Length, out numWrite);
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return ReturnVal;
        }

        public bool WriteStringWPointer(IntPtr BaseAddress, int[] OffsetAddress, string Val)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            bool ReturnVal;

            IntPtr numWrite;
            uint oldProtect;

            IntPtr ActualAddress = GetAddressPointer(BaseAddress, OffsetAddress);

            VirtualProtectEx(hProcess, ActualAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            ReturnVal = WriteProcessMemory(hProcess, ActualAddress, Encoding.Unicode.GetBytes(Val), Encoding.Unicode.GetBytes(Val).Length, out numWrite);
            VirtualProtectEx(hProcess, ActualAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return ReturnVal;
        }

        public int ReadInt(IntPtr BaseAddress)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return -1;
            }

            byte[] buffer = new byte[sizeof(int)];
            IntPtr numRead;
            uint oldProtect;
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(int), 0x40, out oldProtect); //0x40 = page execute read write
            int result = ReadProcessMemory(hProcess, BaseAddress, buffer, sizeof(int), out numRead);
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(int), oldProtect, out oldProtect);

            return BitConverter.ToInt32(buffer, 0);
        }

        public int ReadIntPointer(IntPtr BaseAddress, int[] OffsetAddress)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return -1;
            }

            byte[] buffer = new byte[sizeof(int)];
            IntPtr numRead;
            uint oldProtect;

            IntPtr ActualAddress = GetAddressPointer(BaseAddress, OffsetAddress);

            VirtualProtectEx(hProcess, ActualAddress, (UIntPtr)sizeof(int), 0x40, out oldProtect); //0x40 = page execute read write
            int result = ReadProcessMemory(hProcess, ActualAddress, buffer, sizeof(int), out numRead);
            VirtualProtectEx(hProcess, ActualAddress, (UIntPtr)sizeof(int), oldProtect, out oldProtect);

            return BitConverter.ToInt32(buffer, 0);
        }

        public double ReadDouble(IntPtr BaseAddress)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return -1;
            }

            byte[] buffer = new byte[sizeof(double)];
            IntPtr numRead;
            uint oldProtect;
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(double), 0x40, out oldProtect); //0x40 = page execute read write
            double result = ReadProcessMemory(hProcess, BaseAddress, buffer, sizeof(double), out numRead);
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(double), oldProtect, out oldProtect);

            return BitConverter.ToDouble(buffer, 0);
        }

        public double ReadDoublePointer(IntPtr BaseAddress, int[] OffsetAddress)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return -1;
            }

            byte[] buffer = new byte[sizeof(double)];
            IntPtr numRead;
            uint oldProtect;

            IntPtr ActualAddress = GetAddressPointer(BaseAddress, OffsetAddress);

            VirtualProtectEx(hProcess, ActualAddress, (UIntPtr)sizeof(double), 0x40, out oldProtect); //0x40 = page execute read write
            double result = ReadProcessMemory(hProcess, ActualAddress, buffer, sizeof(double), out numRead);
            VirtualProtectEx(hProcess, ActualAddress, (UIntPtr)sizeof(double), oldProtect, out oldProtect);

            return BitConverter.ToDouble(buffer, 0);
        }

        public float ReadFloat(IntPtr BaseAddress)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return -1;
            }

            byte[] buffer = new byte[sizeof(float)];
            IntPtr numRead;
            uint oldProtect;
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            float result = ReadProcessMemory(hProcess, BaseAddress, buffer, sizeof(float), out numRead);
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return BitConverter.ToSingle(buffer, 0);
        }

        public float ReadFloatPointer(IntPtr BaseAddress, int[] OffsetAddress)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return -1;
            }

            byte[] buffer = new byte[sizeof(float)];
            IntPtr numRead;
            uint oldProtect;

            IntPtr ActualAddress = GetAddressPointer(BaseAddress, OffsetAddress);

            VirtualProtectEx(hProcess, ActualAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            float result = ReadProcessMemory(hProcess, ActualAddress, buffer, sizeof(float), out numRead);
            VirtualProtectEx(hProcess, ActualAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return BitConverter.ToSingle(buffer, 0);
        }

        public byte[] ReadBytes(IntPtr BaseAddress, int Size)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return null;
            }

            byte[] buffer = new byte[Size];
            IntPtr numRead;
            uint oldProtect;
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)Size, 0x40, out oldProtect); //0x40 = page execute read write
            float result = ReadProcessMemory(hProcess, BaseAddress, buffer, (uint)Size, out numRead);
            VirtualProtectEx(hProcess, BaseAddress, (UIntPtr)Size, oldProtect, out oldProtect);

            return buffer;
        }

        public byte[] ReadBytesPointer(IntPtr BaseAddress, int[] OffsetAddress, int Size)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return null;
            }

            byte[] buffer = new byte[Size];
            IntPtr numRead;
            uint oldProtect;

            IntPtr ActualAddress = GetAddressPointer(BaseAddress, OffsetAddress);

            VirtualProtectEx(hProcess, ActualAddress, (UIntPtr)Size, 0x40, out oldProtect); //0x40 = page execute read write
            float result = ReadProcessMemory(hProcess, ActualAddress, buffer, (uint)Size, out numRead);
            VirtualProtectEx(hProcess, ActualAddress, (UIntPtr)Size, oldProtect, out oldProtect);

            return buffer;
        }

        public IntPtr AobScan(byte[] Pattern)
        {
            if (!isValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return IntPtr.Zero;
            }

            MemoryRegion = new List<MEMORY_BASIC_INFORMATION>();
            MemInfo(hProcess);
            IntPtr temp = IntPtr.Zero;
            for (int i = 0; i < MemoryRegion.Count; i++)
            {
                byte[] buff = new byte[MemoryRegion[i].RegionSize];
                ReadProcessMemory(hProcess, MemoryRegion[i].BaseAddress, buff, MemoryRegion[i].RegionSize, out temp);

                IntPtr Result = Scan(buff, Pattern);
                if (Result != IntPtr.Zero)
                    return new IntPtr(MemoryRegion[i].BaseAddress.ToInt32() + Result.ToInt32());
            }
            return IntPtr.Zero;
        }
    }
}