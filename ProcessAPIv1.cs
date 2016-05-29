using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace XenoCoreZ_Trainer_API
{
    internal class ProcessAPIv1
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hHandle);

        public static IntPtr CreateNewProcess(string ExePath, string CMDLine)
        {
            bool retValue;
            var Application = ExePath;
            var CommandLine = CMDLine;
            var pInfo = new PROCESS_INFORMATION();
            var sInfo = new STARTUPINFO();
            var pSec = new SECURITY_ATTRIBUTES();
            var tSec = new SECURITY_ATTRIBUTES();
            pSec.nLength = Marshal.SizeOf(pSec);
            tSec.nLength = Marshal.SizeOf(tSec);

            //Open Notepad
            retValue = CreateProcess(Application, CommandLine,
                ref pSec, ref tSec, false, (uint) CreateProcessFlags.NORMAL_PRIORITY_CLASS,
                IntPtr.Zero, null, ref sInfo, out pInfo);

            return pInfo.hProcess;
        }

        public static IntPtr CreateNewProcessSuspend(string ExePath, string CMDLine)
        {
            bool retValue;
            var Application = ExePath;
            var CommandLine = CMDLine;
            var pInfo = new PROCESS_INFORMATION();
            var sInfo = new STARTUPINFO();
            var pSec = new SECURITY_ATTRIBUTES();
            var tSec = new SECURITY_ATTRIBUTES();
            pSec.nLength = Marshal.SizeOf(pSec);
            tSec.nLength = Marshal.SizeOf(tSec);

            //Open Notepad
            retValue = CreateProcess(Application, CommandLine,
                ref pSec, ref tSec, false, (uint) CreateProcessFlags.CREATE_SUSPENDED,
                IntPtr.Zero, null, ref sInfo, out pInfo);

            return pInfo.hProcess;
        }

        public static void SuspendProcess(int pid)
        {
            var process = Process.GetProcessById(pid);

            if (process.ProcessName == string.Empty)
                return;

            foreach (ProcessThread pT in process.Threads)
            {
                var pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint) pT.Id);

                if (pOpenThread == IntPtr.Zero)
                {
                    continue;
                }

                SuspendThread(pOpenThread);

                CloseHandle(pOpenThread);
            }
        }

        public static void SuspendProcess(string pName)
        {
            var q = Process.GetProcessesByName(pName);
            Process process;

            if (q.Length > 0)
            {
                process = q[0];
            }
            else
            {
                return;
            }

            if (process.ProcessName == string.Empty)
                return;

            foreach (ProcessThread pT in process.Threads)
            {
                var pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint) pT.Id);

                if (pOpenThread == IntPtr.Zero)
                {
                    continue;
                }

                SuspendThread(pOpenThread);

                CloseHandle(pOpenThread);
            }
        }

        public static void ResumeProcess(int pid)
        {
            var process = Process.GetProcessById(pid);

            if (process.ProcessName == string.Empty)
                return;

            foreach (ProcessThread pT in process.Threads)
            {
                var pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint) pT.Id);

                if (pOpenThread == IntPtr.Zero)
                {
                    continue;
                }

                var suspendCount = 0;
                do
                {
                    suspendCount = (int) ResumeThread(pOpenThread);
                } while (suspendCount > 0);

                CloseHandle(pOpenThread);
            }
        }

        public static void ResumeProcess(string pName)
        {
            var q = Process.GetProcessesByName(pName);
            Process process;

            if (q.Length > 0)
            {
                process = q[0];
            }
            else
            {
                return;
            }

            if (process.ProcessName == string.Empty)
                return;

            foreach (ProcessThread pT in process.Threads)
            {
                var pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint) pT.Id);

                if (pOpenThread == IntPtr.Zero)
                {
                    continue;
                }

                var suspendCount = 0;
                do
                {
                    suspendCount = (int) ResumeThread(pOpenThread);
                } while (suspendCount > 0);

                CloseHandle(pOpenThread);
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public readonly int cb;
            public readonly string lpReserved;
            public readonly string lpDesktop;
            public readonly string lpTitle;
            public readonly int dwX;
            public readonly int dwY;
            public readonly int dwXSize;
            public readonly int dwYSize;
            public readonly int dwXCountChars;
            public readonly int dwYCountChars;
            public readonly int dwFillAttribute;
            public readonly int dwFlags;
            public readonly short wShowWindow;
            public readonly short cbReserved2;
            public readonly IntPtr lpReserved2;
            public readonly IntPtr hStdInput;
            public readonly IntPtr hStdOutput;
            public readonly IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public readonly IntPtr hProcess;
            public readonly IntPtr hThread;
            public readonly int dwProcessId;
            public readonly int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public readonly unsafe byte* lpSecurityDescriptor;
            public readonly int bInheritHandle;
        }

        [Flags]
        private enum CreateProcessFlags : uint
        {
            DEBUG_PROCESS = 0x00000001,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            CREATE_SUSPENDED = 0x00000004,
            DETACHED_PROCESS = 0x00000008,
            CREATE_NEW_CONSOLE = 0x00000010,
            NORMAL_PRIORITY_CLASS = 0x00000020,
            IDLE_PRIORITY_CLASS = 0x00000040,
            HIGH_PRIORITY_CLASS = 0x00000080,
            REALTIME_PRIORITY_CLASS = 0x00000100,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_FORCEDOS = 0x00002000,
            BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
            ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
            INHERIT_PARENT_AFFINITY = 0x00010000,
            INHERIT_CALLER_PRIORITY = 0x00020000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
            PROCESS_MODE_BACKGROUND_END = 0x00200000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NO_WINDOW = 0x08000000,
            PROFILE_USER = 0x10000000,
            PROFILE_KERNEL = 0x20000000,
            PROFILE_SERVER = 0x40000000,
            CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000
        }

        [Flags]
        private enum ThreadAccess
        {
            TERMINATE = 0x0001,
            SUSPEND_RESUME = 0x0002,
            GET_CONTEXT = 0x0008,
            SET_CONTEXT = 0x0010,
            SET_INFORMATION = 0x0020,
            QUERY_INFORMATION = 0x0040,
            SET_THREAD_TOKEN = 0x0080,
            IMPERSONATE = 0x0100,
            DIRECT_IMPERSONATION = 0x0200
        }
    }
}