using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace XenoCoreZ_Trainer_API
{
    internal class ProcessApIv1
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            ref SecurityAttributes lpProcessAttributes,
            ref SecurityAttributes lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref Startupinfo lpStartupInfo,
            out ProcessInformation lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hHandle);

        public static IntPtr CreateNewProcess(string exePath, string cmdLine)
        {
            var application = exePath;
            var commandLine = cmdLine;
            ProcessInformation pInfo;
            var sInfo = new Startupinfo();
            var pSec = new SecurityAttributes();
            var tSec = new SecurityAttributes();
            pSec.nLength = Marshal.SizeOf(pSec);
            tSec.nLength = Marshal.SizeOf(tSec);

            //Open Notepad
            CreateProcess(application, commandLine,
                ref pSec, ref tSec, false, (uint)CreateProcessFlags.NormalPriorityClass,
                IntPtr.Zero, null, ref sInfo, out pInfo);

            return pInfo.hProcess;
        }

        public static IntPtr CreateNewProcessSuspend(string exePath, string cmdLine)
        {
            var application = exePath;
            var commandLine = cmdLine;
            ProcessInformation pInfo;
            var sInfo = new Startupinfo();
            var pSec = new SecurityAttributes();
            var tSec = new SecurityAttributes();
            pSec.nLength = Marshal.SizeOf(pSec);
            tSec.nLength = Marshal.SizeOf(tSec);

            //Open Notepad
            CreateProcess(application, commandLine,
                ref pSec, ref tSec, false, (uint)CreateProcessFlags.CreateSuspended,
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
                var pOpenThread = OpenThread(ThreadAccess.SuspendResume, false, (uint)pT.Id);

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
                var pOpenThread = OpenThread(ThreadAccess.SuspendResume, false, (uint)pT.Id);

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
                var pOpenThread = OpenThread(ThreadAccess.SuspendResume, false, (uint)pT.Id);

                if (pOpenThread == IntPtr.Zero)
                {
                    continue;
                }

                int suspendCount;
                do
                {
                    suspendCount = (int)ResumeThread(pOpenThread);
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
                var pOpenThread = OpenThread(ThreadAccess.SuspendResume, false, (uint)pT.Id);

                if (pOpenThread == IntPtr.Zero)
                {
                    continue;
                }

                int suspendCount;
                do
                {
                    suspendCount = (int)ResumeThread(pOpenThread);
                } while (suspendCount > 0);

                CloseHandle(pOpenThread);
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct Startupinfo
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
        private struct ProcessInformation
        {
            public readonly IntPtr hProcess;
            public readonly IntPtr hThread;
            public readonly int dwProcessId;
            public readonly int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            public int nLength;
            public readonly unsafe byte* lpSecurityDescriptor;
            public readonly int bInheritHandle;
        }

        [Flags]
        private enum CreateProcessFlags : uint
        {
            DebugProcess = 0x00000001,
            DebugOnlyThisProcess = 0x00000002,
            CreateSuspended = 0x00000004,
            DetachedProcess = 0x00000008,
            CreateNewConsole = 0x00000010,
            NormalPriorityClass = 0x00000020,
            IdlePriorityClass = 0x00000040,
            HighPriorityClass = 0x00000080,
            RealtimePriorityClass = 0x00000100,
            CreateNewProcessGroup = 0x00000200,
            CreateUnicodeEnvironment = 0x00000400,
            CreateSeparateWowVdm = 0x00000800,
            CreateSharedWowVdm = 0x00001000,
            CreateForcedos = 0x00002000,
            BelowNormalPriorityClass = 0x00004000,
            AboveNormalPriorityClass = 0x00008000,
            InheritParentAffinity = 0x00010000,
            InheritCallerPriority = 0x00020000,
            CreateProtectedProcess = 0x00040000,
            ExtendedStartupinfoPresent = 0x00080000,
            ProcessModeBackgroundBegin = 0x00100000,
            ProcessModeBackgroundEnd = 0x00200000,
            CreateBreakawayFromJob = 0x01000000,
            CreatePreserveCodeAuthzLevel = 0x02000000,
            CreateDefaultErrorMode = 0x04000000,
            CreateNoWindow = 0x08000000,
            ProfileUser = 0x10000000,
            ProfileKernel = 0x20000000,
            ProfileServer = 0x40000000,
            CreateIgnoreSystemDefault = 0x80000000
        }

        [Flags]
        private enum ThreadAccess
        {
            Terminate = 0x0001,
            SuspendResume = 0x0002,
            GetContext = 0x0008,
            SetContext = 0x0010,
            SetInformation = 0x0020,
            QueryInformation = 0x0040,
            SetThreadToken = 0x0080,
            Impersonate = 0x0100,
            DirectImpersonation = 0x0200
        }
    }
}