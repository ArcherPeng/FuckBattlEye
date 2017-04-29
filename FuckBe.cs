using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace FuckBE
{
    static unsafe class FuckBE
    {
        public static void Run(string szCheatPath, string szProcessName)
        {
            Process.EnterDebugMode(); // GET SeDebugPrivilege
            Process procTarget = Process.GetProcessesByName(szProcessName)[0];
            
            var HandleList = EnumHandles(procTarget.Id, 0x1fffff /*FULL_CONTROL*/);

            if (HandleList.Count > 0)
            {
                foreach (var HandleInformation in HandleList)
                {
                    if (HandleInformation.Id == Process.GetCurrentProcess().Id)
                        continue;

                    Process procService = Process.GetProcessById(HandleInformation.Id);

                    Console.WriteLine($"{procService.ProcessName} - {HandleInformation.hProcess.ToString("x2")}");

                    if (ElevateHandle(procService.Handle, HandleInformation.hProcess, true, true))
                    {
                        IntPtr hProcess = StartProcessAsUser(null, $"{szCheatPath} {HandleInformation.hProcess}", null, true, procService.Handle);
                        ElevateHandle(procService.Handle, HandleInformation.hProcess, false, false);
                    }
                }
            }
        }

        private static IntPtr StartProcessAsUser(string szFile, string szArguments, string szDirectory, bool Inherit, IntPtr hParent)
        {
            Win32.STARTUPINFOEX si = new Win32.STARTUPINFOEX();
            Win32.PROCESS_INFORMATION pi = new Win32.PROCESS_INFORMATION();
            Win32.SECURITY_ATTRIBUTES sa = new Win32.SECURITY_ATTRIBUTES();
            
            IntPtr processToken = IntPtr.Zero, userToken, cbAttributeListSize = IntPtr.Zero;
            
            Win32.OpenProcessToken(new IntPtr(-1), (uint)Win32.TOKEN_ACCESS.TOKEN_ALL_ACCESS, ref processToken);
            Win32.DuplicateTokenEx(processToken, (uint)Win32.TOKEN_ACCESS.TOKEN_ALL_ACCESS, out sa, Win32.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, Win32.TOKEN_TYPE.TokenPrimary, out userToken);
            Win32.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref cbAttributeListSize);
            
            IntPtr pAttributeList = Win32.VirtualAlloc(IntPtr.Zero, (int)cbAttributeListSize, 0x1000, 0x40);
            Win32.InitializeProcThreadAttributeList(pAttributeList, 1, 0, ref cbAttributeListSize);
            Win32.UpdateProcThreadAttribute(pAttributeList, 0, (IntPtr)0x00020000, ref hParent, (IntPtr)Marshal.SizeOf(hParent), IntPtr.Zero, IntPtr.Zero);
            
            si.lpAttributeList = pAttributeList;
            si.StartupInfo = new Win32.STARTUPINFO();
            
            Win32.CreateProcessAsUserA(userToken, szFile, szArguments, IntPtr.Zero, IntPtr.Zero, Inherit, 0x400 | 0x010 | 0x00080000, IntPtr.Zero, szDirectory, ref si, ref pi);

            Win32.CloseHandle(processToken);
            Win32.CloseHandle(userToken);
            Win32.DeleteProcThreadAttributeList(pAttributeList);
            Win32.VirtualFree(pAttributeList, 0x1000, 0x8000);

            return pi.hProcess;
            
        }

        struct ShellcodeArguments
        {
            public IntPtr hObject;
            public bool PStatus;
            public bool IStatus;
            public IntPtr pfnNtSetInformationObject;
        }
        private static bool ElevateHandle(IntPtr hProcess, IntPtr hObject, bool Protect, bool Inherit)
        {
            byte[] W64ThreadShellcode = {
                0x48, 0x83, 0xEC, 0x28, 0x0F, 0xB6, 0x41, 0x08, 0x4C, 0x8D, 0x44, 0x24, 0x30, 0x41, 0xB9, 0x02, 0x00, 0x00, 0x00, 0x88, 0x44,
                0x24, 0x31, 0x0F, 0xB6, 0x41, 0x0C, 0x4C, 0x8B, 0xD1, 0x48, 0x8B, 0x09, 0x88, 0x44, 0x24, 0x30, 0x41, 0x8D, 0x51, 0x02, 0x41,
                0xFF, 0x52, 0x10, 0x33, 0xC9, 0x85, 0xC0, 0x0F, 0x94, 0xC1, 0x8B, 0xC1, 0x48, 0x83, 0xC4, 0x28, 0xC3 };

            ShellcodeArguments Args = new ShellcodeArguments {
                hObject = hObject,
                IStatus = Inherit,
                PStatus = Protect,
                pfnNtSetInformationObject = Win32.GetProcAddress(Win32.GetModuleHandleA("ntdll.dll"), "NtSetInformationObject")
            };

            IntPtr WArgs = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.StructureToPtr(Args, WArgs, true);

            IntPtr lpThread = Win32.VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x1000, 0x40);
            IntPtr lpArgs = Win32.VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x1000, 0x40);

            if (lpThread == IntPtr.Zero || lpArgs == IntPtr.Zero)
                return Cleanup(hProcess, lpThread, lpArgs, WArgs);

            fixed (byte* pShellcode = W64ThreadShellcode)
            {
                if (!Win32.WriteProcessMemory(hProcess, lpThread, (IntPtr)pShellcode, W64ThreadShellcode.Length, IntPtr.Zero))
                    return Cleanup(hProcess, lpThread, lpArgs, WArgs);

                if (!Win32.WriteProcessMemory(hProcess, lpArgs, WArgs, Marshal.SizeOf(Args), IntPtr.Zero))
                    return Cleanup(hProcess, lpThread, lpArgs, WArgs);
            }
            
            IntPtr hThread = IntPtr.Zero;
            if (Win32.RtlCreateUserThread(hProcess, IntPtr.Zero, false, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, lpThread, lpArgs, ref hThread, IntPtr.Zero) != 0/*STATUS_SUCCESS*/)
                return Cleanup(hProcess, lpThread, lpArgs, WArgs);

            Win32.WaitForSingleObject(hThread, 0xFFFFFFFF);
            Win32.CloseHandle(hThread);
            Cleanup(hProcess, lpThread, lpArgs, WArgs);

            return true;
        }
        private static bool Cleanup(IntPtr hProcess, IntPtr lpThread, IntPtr lpArgs, IntPtr WArgs)
        {
            Marshal.FreeHGlobal(WArgs);
            Win32.VirtualFreeEx(hProcess, lpThread, 0x1000, 0x8000);
            Win32.VirtualFreeEx(hProcess, lpArgs, 0x1000, 0x8000);
            return false;
        }

        public struct SYSTEM_HANDLE_INFORMATION
        {
            public int Id;
            public IntPtr hProcess;
        }
        public static List<SYSTEM_HANDLE_INFORMATION> EnumHandles(int nProcessId, int DesiredAccess)
        {
            int nBufferLength = 0x10000;
            IntPtr pInfo = Marshal.AllocHGlobal(nBufferLength);
            while (Win32.NtQuerySystemInformation(0x0010/*HANDLE INFORMATION*/, pInfo, nBufferLength, ref nBufferLength) == 0xc0000004/*STATUS_INFO_LENGTH_MISMATCH*/)
            {
                Marshal.FreeHGlobal(pInfo);
                pInfo = Marshal.AllocHGlobal(nBufferLength);
            }
            
            long lHandleCount = Marshal.ReadInt64(pInfo);
            IntPtr pHandle = pInfo + sizeof(long);
            
            List<SYSTEM_HANDLE_INFORMATION> ResultHandles = new List<SYSTEM_HANDLE_INFORMATION>();

            for (int i = 0; i < lHandleCount; i++)
            {
                var CurrentHandle = (Win32.SYSTEM_HANDLE)Marshal.PtrToStructure(pHandle, typeof(Win32.SYSTEM_HANDLE));

                pHandle += Marshal.SizeOf(CurrentHandle);
                
                IntPtr hProcess = Win32.OpenProcess(0x0040, false, CurrentHandle.ProcessID);

                IntPtr hCopiedProcessHandle = IntPtr.Zero;
                if (Win32.DuplicateHandle(hProcess, (IntPtr)CurrentHandle.Handle, new IntPtr(-1), ref hCopiedProcessHandle, 0, false, 2))
                {
                    if (Win32.GetProcessId(hCopiedProcessHandle) == nProcessId && CurrentHandle.Handle != nProcessId)
                    {
                        if ((CurrentHandle.GrantedAccess & DesiredAccess) == DesiredAccess)
                            ResultHandles.Add(new SYSTEM_HANDLE_INFORMATION { Id = CurrentHandle.ProcessID, hProcess = (IntPtr)CurrentHandle.Handle });
                    }
                }
            }
            
            return ResultHandles;
        }

        static class Win32
        {
            #region Structs
            [StructLayout(LayoutKind.Sequential)]
            public struct PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public int dwProcessId;
                public int dwThreadId;
            }
            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct SYSTEM_HANDLE
            {
                public int ProcessID;
                public char ObjectTypeNumber;
                public char Flags;
                public ushort Handle;
                public long Object_Pointer;
                public long GrantedAccess;
            }
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct STARTUPINFO
            {
                public int cb;
                public string lpReserved;
                public string lpDesktop;
                public string lpTitle;
                public int dwX;
                public int dwY;
                public int dwXSize;
                public int dwYSize;
                public int dwXCountChars;
                public int dwYCountChars;
                public int dwFillAttribute;
                public int dwFlags;
                public short wShowWindow;
                public short cbReserved2;
                public IntPtr lpReserved2;
                public IntPtr hStdInput;
                public IntPtr hStdOutput;
                public IntPtr hStdError;
            }

            public struct STARTUPINFOEX
            {
                public STARTUPINFO StartupInfo;
                public IntPtr lpAttributeList;
            }
            public struct SECURITY_ATTRIBUTES
            {
                public int nLength;
                public byte lpSecurityDescriptor;
                public int bInheritHandle;
            }
            #endregion

            #region Enums/Flags
            public enum SECURITY_IMPERSONATION_LEVEL
            {
                SecurityAnonymous,
                SecurityIdentification,
                SecurityImpersonation,
                SecurityDelegation
            }
            public enum TOKEN_TYPE
            {
                TokenPrimary = 1,
                TokenImpersonation
            }
            public enum TOKEN_ACCESS
            {
                STANDARD_RIGHTS_REQUIRED = 0x000F0000,
                STANDARD_RIGHTS_READ = 0x00020000,
                TOKEN_ASSIGN_PRIMARY = 0x0001,
                TOKEN_DUPLICATE = 0x0002,
                TOKEN_IMPERSONATE = 0x0004,
                TOKEN_QUERY = 0x0008,
                TOKEN_QUERY_SOURCE = 0x0010,
                TOKEN_ADJUST_PRIVILEGES = 0x0020,
                TOKEN_ADJUST_GROUPS = 0x0040,
                TOKEN_ADJUST_DEFAULT = 0x0080,
                TOKEN_ADJUST_SESSIONID = 0x0100,
                TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY),
                TOKEN_ALL_ACCESS =
                STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE |
                TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES |
                TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID
            }

            #endregion


            // KERNEL32
            [DllImport("kernel32.dll")]
            public static extern bool CloseHandle(IntPtr hObject);

            [DllImport("kernel32.dll")]
            public static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, int flAllocationType, int flProtect);

            [DllImport("kernel32.dll")]
            public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, int flAllocationType, int flProtect);

            [DllImport("kernel32.dll")]
            public static extern bool VirtualFree(IntPtr lpAddress, int dwSize, int dwFreeType);

            [DllImport("kernel32.dll")]
            public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, int dwFreeType);

            [DllImport("kernel32.dll")]
            public static extern int WaitForSingleObject(IntPtr hObject, UInt32 dwMilliseconds);

            [DllImport("kernel32.dll")]
            public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

            [DllImport("kernel32.dll")]
            public static extern bool OpenProcessToken(IntPtr hProcess, UInt32 DesiredAccess, ref IntPtr TokenHandle);

            [DllImport("kernel32.dll")]
            public static extern int GetProcessId(IntPtr hProcess);

            [DllImport("kernel32.dll")]
            public static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr TargetProcessHandle, ref IntPtr lpTargetHandle, int dwDesiredAccess, bool bInherithandle, int dwOptions);

            [DllImport("kernel32.dll")]
            public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int nSize, IntPtr lpNumberOfBytesWritten);

            [DllImport("kernel32.dll")]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

            [DllImport("kernel32.dll")]
            public static extern IntPtr GetModuleHandleA(string lpModuleName);

            [DllImport("kernel32.dll")]
            public static extern Boolean CreateProcessAsUserA(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, int dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFOEX si, ref PROCESS_INFORMATION pi);

            [DllImport("kernel32.dll")]
            public static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

            [DllImport("kernel32.dll")]
            public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

            [DllImport("kernel32.dll")]
            public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, ref IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

            // NTDLL
            [DllImport("ntdll.dll")]
            public static extern long NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, ref int ReturnLength);

            [DllImport("ntdll.dll")]
            public static extern int RtlCreateUserThread(IntPtr Process, IntPtr ThreadSecurityDescriptor, Boolean CreateSuspended, IntPtr ZeroBits, IntPtr MaximumStackSize, IntPtr CommittedStackSize, IntPtr StartAddress, IntPtr Parameter, ref IntPtr Thread, IntPtr ClientId);

            // ADVAPI
            [DllImport("advapi32.dll")]
            public extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, out SECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, out IntPtr phNewToken);

            [DllImport("userenv.dll")]
            public static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

            [DllImport("userenv.dll")]
            public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);
        }
    }
}
