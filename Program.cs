using System;
using System.Runtime.InteropServices;
using System.IO;


namespace MasqueradePEB
{
    class Program
    {

        public enum PageProtection : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        /// Partial _PEB
        [StructLayout(LayoutKind.Explicit, Size = 64)]
        public struct _PEB
        {
            [FieldOffset(12)]
            public IntPtr Ldr32;
            [FieldOffset(16)]
            public IntPtr ProcessParameters32;
            [FieldOffset(24)]
            public IntPtr Ldr64;
            [FieldOffset(28)]
            public IntPtr FastPebLock32;
            [FieldOffset(32)]
            public IntPtr ProcessParameters64;
            [FieldOffset(56)]
            public IntPtr FastPebLock64;
        }
        
        //PROCESS_BASIC_INFORMATION
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr Reserved3;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }

        //Kernel32
        public static class Kernel32
        {
            [DllImport("kernel32.dll")]
            public static extern UInt32 GetLastError();
            [DllImport("kernel32.dll")]
            public static extern Boolean VirtualProtectEx(
                IntPtr hProcess,
                IntPtr lpAddress,
                UInt32 dwSize,
                PageProtection flNewProtect,
                ref IntPtr lpflOldProtect);
            [DllImport("kernel32.dll")]
            public static extern Boolean WriteProcessMemory(
                IntPtr hProcess,
                IntPtr lpBaseAddress,
                IntPtr lpBuffer,
                UInt32 nSize,
                ref IntPtr lpNumberOfBytesWritten);
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, ref IntPtr lpBuffer, IntPtr dwSize, IntPtr lpNumberOfBytesRead);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, ref UNICODE_STRING lpBuffer, IntPtr dwSize, IntPtr lpNumberOfBytesRead);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [MarshalAs(UnmanagedType.LPWStr)] string lpBuffer, IntPtr dwSize, IntPtr lpNumberOfBytesRead);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GetCurrentProcess();
        }
        //Ntdll
        public static class Ntdll
        {
            [DllImport("ntdll.dll")]
            public static extern int NtQueryInformationProcess(
                IntPtr processHandle,
                int processInformationClass,
                ref PROCESS_BASIC_INFORMATION processInformation,
                int processInformationLength,
                ref int returnLength);

            [DllImport("ntdll.dll")]
            public static extern void RtlEnterCriticalSection(
                IntPtr lpCriticalSection);

            [DllImport("ntdll.dll")]
            public static extern void RtlLeaveCriticalSection(
                IntPtr lpCriticalSection);


        }

        public static IntPtr StructureToPtr(object obj)
        {
            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(obj));
            Marshal.StructureToPtr(obj, ptr, false);
            return ptr;
        }

        public static PROCESS_BASIC_INFORMATION ProcessParameters(int processParametersOffset)
        {
            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            int PROCESS_BASIC_INFORMATION_SIZE = Marshal.SizeOf(bi);
            int returnLengths = 0;
            Int32 Status = Ntdll.NtQueryInformationProcess(Kernel32.GetCurrentProcess(), 0, ref bi, PROCESS_BASIC_INFORMATION_SIZE, ref returnLengths);
            Console.WriteLine("[+] ProcessId:" + bi.UniqueProcessId);
            if (Status == (Int32)NtStatus.Success)
            {

                Console.WriteLine("[+] PebBaseAddress:" + bi.PebBaseAddress.ToString("X"));
                foreach (var status in Enum.GetValues(typeof(NtStatus)))
                {
                    if (Status == Convert.ToInt32(status.GetHashCode()))
                    {
                        Console.WriteLine("[+] NtStatus:" + status);
                    }
                }
                //ReadMemory from and ProcessParameter

                IntPtr pp = new IntPtr();
                Kernel32.ReadProcessMemory(Kernel32.GetCurrentProcess(), bi.PebBaseAddress + processParametersOffset, ref pp, new IntPtr(Marshal.SizeOf(pp)), IntPtr.Zero);
                UNICODE_STRING us = new UNICODE_STRING();
                Console.WriteLine("[+] CurrentProcessParameter");
                if (processParametersOffset == 0x20)
                {
                    Console.WriteLine("x64 on x64");
                    foreach (var Parameter in Enum.GetValues(typeof(ProcessParametersx64)))
                    {
                        Kernel32.ReadProcessMemory(Kernel32.GetCurrentProcess(), pp + Parameter.GetHashCode(), ref us, new IntPtr(Marshal.SizeOf(us)), IntPtr.Zero);
                        string s = new string('\0', us.Length / 2);
                        Kernel32.ReadProcessMemory(Kernel32.GetCurrentProcess(), us.buffer, s, new IntPtr(us.Length), IntPtr.Zero);
                        Console.WriteLine("  [-] " + Parameter.ToString() + ":" + s);
                    }
                }
                else
                {
                    Console.WriteLine("x86 on x64");
                    foreach (var Parameter in Enum.GetValues(typeof(ProcessParametersx86)))
                    {
                        Kernel32.ReadProcessMemory(Kernel32.GetCurrentProcess(), pp + Parameter.GetHashCode(), ref us, new IntPtr(Marshal.SizeOf(us)), IntPtr.Zero);
                        string s = new string('\0', us.Length / 2);
                        Kernel32.ReadProcessMemory(Kernel32.GetCurrentProcess(), us.buffer, s, new IntPtr(us.Length), IntPtr.Zero);
                        Console.WriteLine("  [-] " + Parameter.ToString() + ":" + s);
                    }
                }
            }
            else
            {
                Console.WriteLine("[+] NtStatus:" + Status);
            }
            return bi;
        }

        public static void McfInitUnicodeString(IntPtr procHandle, IntPtr lpDestAddress, string uniStr)
        {
            UNICODE_STRING masq = new UNICODE_STRING(uniStr);
            IntPtr masqPtr = StructureToPtr(masq);
            IntPtr lpflOldProtect = IntPtr.Zero;
            IntPtr lpNumberOfBytesWritten = IntPtr.Zero;

            Kernel32.VirtualProtectEx(procHandle, lpDestAddress, (uint)Marshal.SizeOf(typeof(UNICODE_STRING)), PageProtection.PAGE_EXECUTE_READWRITE, ref lpflOldProtect);
            Kernel32.WriteProcessMemory(procHandle, lpDestAddress, masqPtr, (uint)Marshal.SizeOf(typeof(UNICODE_STRING)), ref lpNumberOfBytesWritten);
            Kernel32.VirtualProtectEx(procHandle, lpDestAddress, (uint)Marshal.SizeOf(typeof(UNICODE_STRING)), PageProtection.PAGE_EXECUTE_READ, ref lpflOldProtect);
        }

        public static void MasqueradePEB(PROCESS_BASIC_INFORMATION pb, String BinPaths,int processParametersOffset) {
            IntPtr pbiPtr = IntPtr.Zero;
            IntPtr pebPtr = IntPtr.Zero;
            int result = 0;
            _PEB peb;

            pbiPtr = StructureToPtr(pb);
            Int32 Status = Ntdll.NtQueryInformationProcess(Kernel32.GetCurrentProcess(), 0, ref pb, Marshal.SizeOf(pb), ref result);
            pb = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pbiPtr, typeof(PROCESS_BASIC_INFORMATION));
            peb = (_PEB)Marshal.PtrToStructure(pb.PebBaseAddress, typeof(_PEB));

            IntPtr PROCESS_PARAMETERS = IntPtr.Zero;

            UNICODE_STRING masq = new UNICODE_STRING(BinPaths);
            IntPtr masqPtr = StructureToPtr(masq);
            IntPtr lpflOldProtect = IntPtr.Zero;
            IntPtr lpNumberOfBytesWritten = IntPtr.Zero;

            String CurrentDirectory = Path.GetDirectoryName(BinPaths);
            String ImagePathName = BinPaths;
            String CommandLine = Path.GetFileName(BinPaths);
            String WindowTitle = Path.GetFileName(BinPaths);


            if (processParametersOffset == 0x20)
            {
                PROCESS_PARAMETERS = peb.ProcessParameters64;
                Ntdll.RtlEnterCriticalSection(peb.FastPebLock64);
                Console.WriteLine("[+] ModifyFakeProcessParameter");
                McfInitUnicodeString(Kernel32.GetCurrentProcess(), PROCESS_PARAMETERS + ProcessParametersx64.CurrentDirectory.GetHashCode(), CurrentDirectory);
                McfInitUnicodeString(Kernel32.GetCurrentProcess(), PROCESS_PARAMETERS + ProcessParametersx64.ImagePathName.GetHashCode(), ImagePathName);
                McfInitUnicodeString(Kernel32.GetCurrentProcess(), PROCESS_PARAMETERS + ProcessParametersx64.CommandLine.GetHashCode(), CommandLine);
                McfInitUnicodeString(Kernel32.GetCurrentProcess(), PROCESS_PARAMETERS + ProcessParametersx64.WindowTitle.GetHashCode(), WindowTitle);
                Ntdll.RtlEnterCriticalSection(peb.FastPebLock64);
            }
            else
            {
                PROCESS_PARAMETERS = peb.ProcessParameters32;
                Ntdll.RtlEnterCriticalSection(peb.FastPebLock32);
                Console.WriteLine("[+] ModifyFakeProcessParameter");
                McfInitUnicodeString(Kernel32.GetCurrentProcess(), PROCESS_PARAMETERS + ProcessParametersx86.CurrentDirectory.GetHashCode(), CurrentDirectory);
                McfInitUnicodeString(Kernel32.GetCurrentProcess(), PROCESS_PARAMETERS + ProcessParametersx86.ImagePathName.GetHashCode(), ImagePathName);
                McfInitUnicodeString(Kernel32.GetCurrentProcess(), PROCESS_PARAMETERS + ProcessParametersx86.CommandLine.GetHashCode(), CommandLine);
                McfInitUnicodeString(Kernel32.GetCurrentProcess(), PROCESS_PARAMETERS + ProcessParametersx86.WindowTitle.GetHashCode(), WindowTitle);
                Ntdll.RtlEnterCriticalSection(peb.FastPebLock32);
            }

        }


        static void Main(string[] args)
        {
            int processParametersOffset = Environment.Is64BitOperatingSystem && Environment.Is64BitProcess ? 0x20 : 0x10;
            String BinPath = @"C:\Windows\explorer.exe";
            PROCESS_BASIC_INFORMATION pbi = ProcessParameters(processParametersOffset);
            MasqueradePEB(pbi, BinPath, processParametersOffset);
            ProcessParameters(processParametersOffset);
            Environment.Exit(0);
        }
    }
}