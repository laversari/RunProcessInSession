using System;
using System.Diagnostics;

namespace RunProcessInSession
{
    class Program
    {
        static void Main(string[] args)
        {
            //ARGS
            string process = args[0];

            UInt32 session = Convert.ToUInt32(args[1]);
            
            string processArgs = String.Empty;

            //if (args.Length > 1)
            //{
            //    processArgs = String.Join(" ", args.Skip(1)
            //        .Select((a) => "\"" + a + "\""));
            //}
           
            IntPtr currentToken = IntPtr.Zero;
                 
            WinApi.OpenProcessToken(Process.GetCurrentProcess().Handle,
                WinApi.TOKEN_DUPLICATE, out currentToken);

            IntPtr newToken = IntPtr.Zero;

            #region DONT TOUCH

            WinApi.DuplicateTokenEx(currentToken, (uint)WinApi.ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero, WinApi.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                WinApi.TOKEN_TYPE.TokenPrimary, out newToken);

            //UInt32 dwSession = 3; //WinApi.WTSGetActiveConsoleSessionId(); 

   
            WinApi.SetTokenInformation(newToken, WinApi.TOKEN_INFORMATION_CLASS.TokenSessionId,
                ref session, (UInt32) IntPtr.Size);

            WinApi.PROCESS_INFORMATION pi = new WinApi.PROCESS_INFORMATION();
            WinApi.STARTUPINFO si = new WinApi.STARTUPINFO();

            string commandline = "\"" + process + "\" " + processArgs;

            WinApi.CreateProcessAsUser(newToken, null, commandline, IntPtr.Zero, IntPtr.Zero,
            false, (uint)WinApi.CreateProcessFlags.CREATE_NEW_CONSOLE,
            IntPtr.Zero, null, ref si, out pi);

            #endregion

        }
    }
}
