using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace XenoCoreZ_Trainer_API
{
    public class AobScanExApIv1
    {
        /// USAGE
        ///
        ///var sigscan = new AOBScanExAPIv1(YourProcObject.Handle, SomeBaseAddress, SomeSize);
        ///var addr = sigscan.FindPattern(new byte[] { 0x53, 0x56, 0x57, 0xA1, 0x0xFF, 0x0xFF, 0x0xFF, 0x0xFF, 0x31, 0x45, 0xFC, 0x33, 0xC5, 0x50 }, "xxxx????xxxxxx", 4);

        /// <summary>
        /// ReadProcessMemory
        ///
        ///     API import definition for ReadProcessMemory.
        /// </summary>
        /// <param name="hProcess">Handle to the process we want to read from.</param>
        /// <param name="lpBaseAddress">The base address to start reading from.</param>
        /// <param name="lpBuffer">The return buffer to write the read data to.</param>
        /// <param name="dwSize">The size of data we wish to read.</param>
        /// <param name="lpNumberOfBytesRead">The number of bytes successfully read.</param>
        /// <returns></returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out int lpNumberOfBytesRead
            );

        /// <summary>
        /// m_vDumpedRegion
        ///
        ///     The memory dumped from the external process.
        /// </summary>
        private byte[] _mVDumpedRegion;

        /// <summary>
        /// m_vProcess
        ///
        ///     The process we want to read the memory of.
        /// </summary>
        private Process _mVProcess;

        /// <summary>
        /// m_vAddress
        ///
        ///     The starting address we want to begin reading at.
        /// </summary>
        private IntPtr _mVAddress;

        /// <summary>
        /// m_vSize
        ///
        ///     The number of bytes we wish to read from the process.
        /// </summary>
        private int _mVSize;

        #region "sigScan Class Construction"

        /// <summary>
        /// SigScan
        ///
        ///     Main class constructor that uses no params.
        ///     Simply initializes the class properties and
        ///     expects the user to set them later.
        /// </summary>
        public AobScanExApIv1()
        {
            _mVProcess = null;
            _mVAddress = IntPtr.Zero;
            _mVSize = 0;
            _mVDumpedRegion = null;
        }

        /// <summary>
        /// SigScan
        ///
        ///     Overloaded class constructor that sets the class
        ///     properties during construction.
        /// </summary>
        /// <param name="proc">The process to dump the memory from.</param>
        /// <param name="addr">The started address to begin the dump.</param>
        /// <param name="size">The size of the dump.</param>
        public AobScanExApIv1(Process proc, IntPtr addr, int size)
        {
            _mVProcess = proc;
            _mVAddress = addr;
            _mVSize = size;
        }

        #endregion "sigScan Class Construction"

        #region "sigScan Class Private Methods"

        /// <summary>
        /// DumpMemory
        ///
        ///     Internal memory dump function that uses the set class
        ///     properties to dump a memory region.
        /// </summary>
        /// <returns>Boolean based on RPM results and valid properties.</returns>
        private bool DumpMemory()
        {
            try
            {
                // Checks to ensure we have valid data.
                if (_mVProcess == null)
                    return false;
                if (_mVProcess.HasExited)
                    return false;
                if (_mVAddress == IntPtr.Zero)
                    return false;
                if (_mVSize == 0)
                    return false;

                // Create the region space to dump into.
                _mVDumpedRegion = new byte[_mVSize];

                int nBytesRead;

                // Dump the memory.
                var ret = ReadProcessMemory(
                    _mVProcess.Handle, _mVAddress, _mVDumpedRegion, _mVSize, out nBytesRead
                    );

                // Validation checks.
                return ret && nBytesRead == _mVSize;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// MaskCheck
        ///
        ///     Compares the current pattern byte to the current memory dump
        ///     byte to check for a match. Uses wildcards to skip bytes that
        ///     are deemed unneeded in the compares.
        /// </summary>
        /// <param name="nOffset">Offset in the dump to start at.</param>
        /// <param name="btPattern">Pattern to scan for.</param>
        /// <param name="strMask">Mask to compare against.</param>
        /// <returns>Boolean depending on if the pattern was found.</returns>
        private bool MaskCheck(int nOffset, IEnumerable<byte> btPattern, string strMask)
        {
            // Loop the pattern and compare to the mask and dump.
            return !btPattern.Where((t, x) => strMask[x] != '?' && ((strMask[x] == 'x') && (t != _mVDumpedRegion[nOffset + x]))).Any();

            // The loop was successful so we found the pattern.
        }

        #endregion "sigScan Class Private Methods"

        #region "sigScan Class Public Methods"

        /// <summary>
        /// FindPattern
        ///
        ///     Attempts to locate the given pattern inside the dumped memory region
        ///     compared against the given mask. If the pattern is found, the offset
        ///     is added to the located address and returned to the user.
        /// </summary>
        /// <param name="btPattern">Byte pattern to look for in the dumped region.</param>
        /// <param name="strMask">The mask string to compare against.</param>
        /// <param name="nOffset">The offset added to the result address.</param>
        /// <returns>IntPtr - zero if not found, address if found.</returns>
        public IntPtr FindPattern(byte[] btPattern, string strMask, int nOffset)
        {
            try
            {
                // Dump the memory region if we have not dumped it yet.
                if (_mVDumpedRegion == null || _mVDumpedRegion.Length == 0)
                {
                    if (!DumpMemory())
                        return IntPtr.Zero;
                }

                // Ensure the mask and pattern lengths match.
                if (strMask.Length != btPattern.Length)
                    return IntPtr.Zero;

                // Loop the region and look for the pattern.
                for (int x = 0; x < _mVDumpedRegion.Length; x++)
                {
                    if (MaskCheck(x, btPattern, strMask))
                    {
                        // The pattern was found, return it.
                        return new IntPtr((int)_mVAddress + (x + nOffset));
                    }
                }

                // Pattern was not found.
                return IntPtr.Zero;
            }
            catch (Exception)
            {
                return IntPtr.Zero;
            }
        }

        /// <summary>
        /// ResetRegion
        ///
        ///     Resets the memory dump array to nothing to allow
        ///     the class to redump the memory.
        /// </summary>
        public void ResetRegion()
        {
            _mVDumpedRegion = null;
        }

        #endregion "sigScan Class Public Methods"

        #region "sigScan Class Properties"

        public Process Process
        {
            get { return _mVProcess; }
            set { _mVProcess = value; }
        }

        public IntPtr Address
        {
            get { return _mVAddress; }
            set { _mVAddress = value; }
        }

        public int Size
        {
            get { return _mVSize; }
            set { _mVSize = value; }
        }

        #endregion "sigScan Class Properties"
    }
}