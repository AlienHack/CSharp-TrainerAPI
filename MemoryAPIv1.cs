using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;
using static System.String;

namespace XenoCoreZ_Trainer_API
{
    internal class MemoryApIv1
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
        public struct MemoryBasicInformation
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public uint RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        private List<MemoryBasicInformation> MemoryRegion { get; set; }

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

        [DllImport("kernel32.dll")]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MemoryBasicInformation lpBuffer, int dwLength);

        private void MemInfo(IntPtr pHandle)
        {
            IntPtr addy = new IntPtr();
            while (true)
            {
                MemoryBasicInformation memInfo = new MemoryBasicInformation();
                int memDump = VirtualQueryEx(pHandle, addy, out memInfo, Marshal.SizeOf(memInfo));
                if (memDump == 0) break;
                if ((memInfo.State & 0x1000) != 0 && (memInfo.Protect & 0x100) == 0)
                    MemoryRegion.Add(memInfo);
                addy = new IntPtr(memInfo.BaseAddress.ToInt32() + (int)memInfo.RegionSize);
            }
        }

        private IntPtr Scan(byte[] sIn, byte[] sFor)
        {
            int[] sBytes = new int[256]; int pool = 0;
            int end = sFor.Length - 1;
            for (int i = 0; i < 256; i++)
                sBytes[i] = sFor.Length;
            for (int i = 0; i < end; i++)
                sBytes[sFor[i]] = end - i;
            while (pool <= sIn.Length - sFor.Length)
            {
                for (int i = end; sIn[pool + i] == sFor[i]; i--)
                    if (i == 0) return new IntPtr(pool);
                pool += sBytes[sIn[pool + end]];
            }
            return IntPtr.Zero;
        }

        private bool IsValid()
        {
            if (_hProcess == IntPtr.Zero)
            {
                return false;
            }
            return true;
        }

        //Required Variable
        private static uint _pid;

        private static IntPtr _hProcess = IntPtr.Zero;
        private static string _pModuleName;

        //Constructor
        public MemoryApIv1(string gameWindowTitle, string gameExecutable, string moduleName)
        {
            _pModuleName = moduleName;

            //Predefined Initializing
            var windowHandle = FindWindow(null, gameWindowTitle);

            if (windowHandle == 0)
            {
                foreach (Process p in Process.GetProcessesByName(gameExecutable))
                {
                    _pid = (uint)p.Id;
                    break;
                }
                if (_pid == 0)
                {
                    MessageBox.Show("Game not found...\n\nReason: PID=0");
                    return;
                }
            }
            else
            {
                GetWindowThreadProcessId((IntPtr)windowHandle, out _pid);
            }
            _hProcess = GetBaseModule(moduleName);

            if (_hProcess == IntPtr.Zero)
            {
                MessageBox.Show("Cant get process handle...\n\nReason: hProcess=0");
            }
        }

        //Functions
        public IntPtr GetBaseModule(string moduleName)
        {
            Process p = Process.GetProcessById((int)_pid);
            foreach (ProcessModule pm in p.Modules)
            {
                if (CompareOrdinal(pm.ModuleName, moduleName) == 0)
                {
                    return pm.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }

        public IntPtr GetBaseModule()
        {
            Process p = Process.GetProcessById((int)_pid);
            foreach (ProcessModule pm in p.Modules)
            {
                if (Compare(pm.ModuleName, _pModuleName) == 0)
                {
                    return pm.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }

        public IntPtr GetAddressPointer(IntPtr baseAddress, int[] offsets)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return IntPtr.Zero;
            }
            return offsets.Aggregate(baseAddress, (current, myOffset) => (IntPtr) (ReadInt(current) + myOffset));
        }

        public bool WriteByteArray(IntPtr baseAddress, byte[] newVal)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(_hProcess, baseAddress, (UIntPtr)newVal.Length, 0x40, out oldProtect); //0x40 = page execute read write
            var returnVal = WriteProcessMemory(_hProcess, baseAddress, newVal, newVal.Length, out numWrite);
            VirtualProtectEx(_hProcess, baseAddress, (UIntPtr)newVal.Length, oldProtect, out oldProtect);

            return returnVal;
        }

        public bool WriteByteArrayPointer(IntPtr baseAddress, int[] offsetAddress, byte[] newVal)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            IntPtr numWrite;
            uint oldProtect;

            IntPtr actualAddress = GetAddressPointer(baseAddress, offsetAddress);

            VirtualProtectEx(_hProcess, actualAddress, (UIntPtr)newVal.Length, 0x40, out oldProtect); //0x40 = page execute read write
            var returnVal = WriteProcessMemory(_hProcess, actualAddress, newVal, newVal.Length, out numWrite);
            VirtualProtectEx(_hProcess, actualAddress, (UIntPtr)newVal.Length, oldProtect, out oldProtect);

            return returnVal;
        }

        public bool WriteInt(IntPtr baseAddress, int val)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(_hProcess, baseAddress, (UIntPtr)sizeof(int), 0x40, out oldProtect); //0x40 = page execute read write
            var returnVal = WriteProcessMemory(_hProcess, baseAddress, BitConverter.GetBytes(val), sizeof(int), out numWrite);
            VirtualProtectEx(_hProcess, baseAddress, (UIntPtr)sizeof(int), oldProtect, out oldProtect);

            return returnVal;
        }

        public bool WriteIntPointer(IntPtr baseAddress, int[] offsetAddress, int val)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            IntPtr numWrite;
            uint oldProtect;

            IntPtr actualAddress = GetAddressPointer(baseAddress, offsetAddress);

            VirtualProtectEx(_hProcess, actualAddress, (UIntPtr)sizeof(int), 0x40, out oldProtect); //0x40 = page execute read write
            var returnVal = WriteProcessMemory(_hProcess, actualAddress, BitConverter.GetBytes(val), sizeof(int), out numWrite);
            VirtualProtectEx(_hProcess, actualAddress, (UIntPtr)sizeof(int), oldProtect, out oldProtect);

            return returnVal;
        }

        public bool WriteDouble(IntPtr baseAddress, double val)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(_hProcess, baseAddress, (UIntPtr)sizeof(double), 0x40, out oldProtect); //0x40 = page execute read write
            var returnVal = WriteProcessMemory(_hProcess, baseAddress, BitConverter.GetBytes(val), sizeof(double), out numWrite);
            VirtualProtectEx(_hProcess, baseAddress, (UIntPtr)sizeof(double), oldProtect, out oldProtect);

            return returnVal;
        }

        public bool WriteDoublePointer(IntPtr baseAddress, int[] offsetAddress, double val)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            IntPtr numWrite;
            uint oldProtect;

            IntPtr actualAddress = GetAddressPointer(baseAddress, offsetAddress);

            VirtualProtectEx(_hProcess, actualAddress, (UIntPtr)sizeof(double), 0x40, out oldProtect); //0x40 = page execute read write
            var returnVal = WriteProcessMemory(_hProcess, actualAddress, BitConverter.GetBytes(val), sizeof(double), out numWrite);
            VirtualProtectEx(_hProcess, actualAddress, (UIntPtr)sizeof(double), oldProtect, out oldProtect);

            return returnVal;
        }

        public bool WriteFloat(IntPtr baseAddress, float val)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(_hProcess, baseAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            var returnVal = WriteProcessMemory(_hProcess, baseAddress, BitConverter.GetBytes(val), sizeof(float), out numWrite);
            VirtualProtectEx(_hProcess, baseAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return returnVal;
        }

        public bool WriteFloatPointer(IntPtr baseAddress, int[] offsetAddress, float val)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            IntPtr numWrite;
            uint oldProtect;

            IntPtr actualAddress = GetAddressPointer(baseAddress, offsetAddress);

            VirtualProtectEx(_hProcess, actualAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            var returnVal = WriteProcessMemory(_hProcess, actualAddress, BitConverter.GetBytes(val), sizeof(float), out numWrite);
            VirtualProtectEx(_hProcess, actualAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return returnVal;
        }

        public bool WriteStringA(IntPtr baseAddress, string val)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(_hProcess, baseAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            var returnVal = WriteProcessMemory(_hProcess, baseAddress, Encoding.ASCII.GetBytes(val), Encoding.ASCII.GetBytes(val).Length, out numWrite);
            VirtualProtectEx(_hProcess, baseAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return returnVal;
        }

        public bool WriteStringAPointer(IntPtr baseAddress, int[] offsetAddress, string val)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            IntPtr numWrite;
            uint oldProtect;

            IntPtr actualAddress = GetAddressPointer(baseAddress, offsetAddress);

            VirtualProtectEx(_hProcess, actualAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            var returnVal = WriteProcessMemory(_hProcess, actualAddress, Encoding.ASCII.GetBytes(val), Encoding.ASCII.GetBytes(val).Length, out numWrite);
            VirtualProtectEx(_hProcess, actualAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return returnVal;
        }

        public bool WriteStringW(IntPtr baseAddress, string val)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            IntPtr numWrite;
            uint oldProtect;

            VirtualProtectEx(_hProcess, baseAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            var returnVal = WriteProcessMemory(_hProcess, baseAddress, Encoding.Unicode.GetBytes(val), Encoding.Unicode.GetBytes(val).Length, out numWrite);
            VirtualProtectEx(_hProcess, baseAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return returnVal;
        }

        public bool WriteStringWPointer(IntPtr baseAddress, int[] offsetAddress, string val)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return false;
            }

            IntPtr numWrite;
            uint oldProtect;

            IntPtr actualAddress = GetAddressPointer(baseAddress, offsetAddress);

            VirtualProtectEx(_hProcess, actualAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            var returnVal = WriteProcessMemory(_hProcess, actualAddress, Encoding.Unicode.GetBytes(val), Encoding.Unicode.GetBytes(val).Length, out numWrite);
            VirtualProtectEx(_hProcess, actualAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return returnVal;
        }

        public int ReadInt(IntPtr baseAddress)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return -1;
            }

            byte[] buffer = new byte[sizeof(int)];
            IntPtr numRead;
            uint oldProtect;
            VirtualProtectEx(_hProcess, baseAddress, (UIntPtr)sizeof(int), 0x40, out oldProtect); //0x40 = page execute read write
            ReadProcessMemory(_hProcess, baseAddress, buffer, sizeof(int), out numRead);
            VirtualProtectEx(_hProcess, baseAddress, (UIntPtr)sizeof(int), oldProtect, out oldProtect);

            return BitConverter.ToInt32(buffer, 0);
        }

        public int ReadIntPointer(IntPtr baseAddress, int[] offsetAddress)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return -1;
            }

            byte[] buffer = new byte[sizeof(int)];
            IntPtr numRead;
            uint oldProtect;

            IntPtr actualAddress = GetAddressPointer(baseAddress, offsetAddress);

            VirtualProtectEx(_hProcess, actualAddress, (UIntPtr)sizeof(int), 0x40, out oldProtect); //0x40 = page execute read write
            ReadProcessMemory(_hProcess, actualAddress, buffer, sizeof(int), out numRead);
            VirtualProtectEx(_hProcess, actualAddress, (UIntPtr)sizeof(int), oldProtect, out oldProtect);

            return BitConverter.ToInt32(buffer, 0);
        }

        public double ReadDouble(IntPtr baseAddress)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return -1;
            }

            byte[] buffer = new byte[sizeof(double)];
            IntPtr numRead;
            uint oldProtect;
            VirtualProtectEx(_hProcess, baseAddress, (UIntPtr)sizeof(double), 0x40, out oldProtect); //0x40 = page execute read write
            ReadProcessMemory(_hProcess, baseAddress, buffer, sizeof(double), out numRead);
            VirtualProtectEx(_hProcess, baseAddress, (UIntPtr)sizeof(double), oldProtect, out oldProtect);

            return BitConverter.ToDouble(buffer, 0);
        }

        public double ReadDoublePointer(IntPtr baseAddress, int[] offsetAddress)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return -1;
            }

            byte[] buffer = new byte[sizeof(double)];
            IntPtr numRead;
            uint oldProtect;

            IntPtr actualAddress = GetAddressPointer(baseAddress, offsetAddress);

            VirtualProtectEx(_hProcess, actualAddress, (UIntPtr)sizeof(double), 0x40, out oldProtect); //0x40 = page execute read write
            ReadProcessMemory(_hProcess, actualAddress, buffer, sizeof(double), out numRead);
            VirtualProtectEx(_hProcess, actualAddress, (UIntPtr)sizeof(double), oldProtect, out oldProtect);

            return BitConverter.ToDouble(buffer, 0);
        }

        public float ReadFloat(IntPtr baseAddress)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return -1;
            }

            byte[] buffer = new byte[sizeof(float)];
            IntPtr numRead;
            uint oldProtect;
            VirtualProtectEx(_hProcess, baseAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            ReadProcessMemory(_hProcess, baseAddress, buffer, sizeof(float), out numRead);
            VirtualProtectEx(_hProcess, baseAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return BitConverter.ToSingle(buffer, 0);
        }

        public float ReadFloatPointer(IntPtr baseAddress, int[] offsetAddress)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return -1;
            }

            byte[] buffer = new byte[sizeof(float)];
            IntPtr numRead;
            uint oldProtect;

            IntPtr actualAddress = GetAddressPointer(baseAddress, offsetAddress);

            VirtualProtectEx(_hProcess, actualAddress, (UIntPtr)sizeof(float), 0x40, out oldProtect); //0x40 = page execute read write
            ReadProcessMemory(_hProcess, actualAddress, buffer, sizeof(float), out numRead);
            VirtualProtectEx(_hProcess, actualAddress, (UIntPtr)sizeof(float), oldProtect, out oldProtect);

            return BitConverter.ToSingle(buffer, 0);
        }

        public byte[] ReadBytes(IntPtr baseAddress, int size)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return null;
            }

            byte[] buffer = new byte[size];
            IntPtr numRead;
            uint oldProtect;
            VirtualProtectEx(_hProcess, baseAddress, (UIntPtr)size, 0x40, out oldProtect); //0x40 = page execute read write
            ReadProcessMemory(_hProcess, baseAddress, buffer, (uint)size, out numRead);
            VirtualProtectEx(_hProcess, baseAddress, (UIntPtr)size, oldProtect, out oldProtect);

            return buffer;
        }

        public byte[] ReadBytesPointer(IntPtr baseAddress, int[] offsetAddress, int size)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return null;
            }

            byte[] buffer = new byte[size];
            IntPtr numRead;
            uint oldProtect;

            IntPtr actualAddress = GetAddressPointer(baseAddress, offsetAddress);

            VirtualProtectEx(_hProcess, actualAddress, (UIntPtr)size, 0x40, out oldProtect); //0x40 = page execute read write
            ReadProcessMemory(_hProcess, actualAddress, buffer, (uint)size, out numRead);
            VirtualProtectEx(_hProcess, actualAddress, (UIntPtr)size, oldProtect, out oldProtect);

            return buffer;
        }

        public IntPtr AobScan(byte[] pattern)
        {
            if (!IsValid())
            {
                MessageBox.Show("Invalid hProcess/n/nReason: hProcess=0");
                return IntPtr.Zero;
            }

            MemoryRegion = new List<MemoryBasicInformation>();
            MemInfo(_hProcess);
            for (int i = 0; i < MemoryRegion.Count; i++)
            {
                byte[] buff = new byte[MemoryRegion[i].RegionSize];
                IntPtr temp;
                ReadProcessMemory(_hProcess, MemoryRegion[i].BaseAddress, buff, MemoryRegion[i].RegionSize, out temp);

                IntPtr result = Scan(buff, pattern);
                if (result != IntPtr.Zero)
                    return new IntPtr(MemoryRegion[i].BaseAddress.ToInt32() + result.ToInt32());
            }
            return IntPtr.Zero;
        }
    }
}