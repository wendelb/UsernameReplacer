using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Configuration;
using System.Text;

namespace UsernameReplacer
{
    class Program
    {

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetUserName(StringBuilder sb, ref Int32 length);

        static void PrintUserName()
        {
            StringBuilder Buffer = new StringBuilder(64);
            int nSize = 64;
            GetUserName(Buffer, ref nSize);
            Console.Write("The current user is: ");
            Console.WriteLine(Buffer.ToString());
        }

        static void Main(string[] args)
        {
            PrintUserName();

            // Will contain the name of the IPC server channel
            string channelName = null;
            Int32 targetPID = 0;

            string targetExe = ConfigurationManager.AppSettings["TargetExe"].ToString();
            string ExeParams = ConfigurationManager.AppSettings["Params"].ToString();
            string ReplaceUsername = ConfigurationManager.AppSettings["UserName"].ToString();
            string ReplaceDomain = ConfigurationManager.AppSettings["Domain"].ToString();

            // Create the IPC server using the FileMonitorIPC.ServiceInterface class as a singleton
            EasyHook.RemoteHooking.IpcCreateServer<UsernameHook.ServerInterface>(ref channelName, System.Runtime.Remoting.WellKnownObjectMode.Singleton);

            // Get the full path to the assembly we want to inject into the target process
            string injectionLibrary = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "UsernameHook.dll");


            try
            {
                Console.WriteLine("Attempting to create and inject into {0}", targetExe);
                // start and inject into a new process
                EasyHook.RemoteHooking.CreateAndInject(
                    targetExe,          // executable to run
                    ExeParams,          // command line arguments for target
                    0,                  // additional process creation flags to pass to CreateProcess
                    EasyHook.InjectionOptions.DoNotRequireStrongName, // allow injectionLibrary to be unsigned
                    injectionLibrary,   // 32-bit library to inject (if target is 32-bit)
                    injectionLibrary,   // 64-bit library to inject (if target is 64-bit)
                    out targetPID,      // retrieve the newly created process ID
                    // the parameters to pass into injected library
                    channelName,        // Channel for Communication
                    ReplaceUsername,    // Username
                    ReplaceDomain       // Domain
                );
            }
            catch (Exception e)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("There was an error while injecting into target:");
                Console.ResetColor();
                Console.WriteLine(e.ToString());
            }

            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("<Press any key to exit>");
            Console.ResetColor();
            Console.ReadKey();
        }
    }
}
