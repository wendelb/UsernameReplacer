using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace UsernameHook
{
    /// <summary>
    /// EasyHook will look for a class implementing <see cref="EasyHook.IEntryPoint"/> during injection. This
    /// becomes the entry point within the target process after injection is complete.
    /// </summary>
    public class InjectionEntryPoint : EasyHook.IEntryPoint
    {
        /// <summary>
        /// Reference to the server interface within UsernameReplacer
        /// </summary>
        ServerInterface _server = null;

        /// <summary>
        /// Stores the Username, that will be returned to every calling process
        /// </summary>
        string _ReplaceUsername = "";

        /// <summary>
        /// Message queue of all files accessed
        /// </summary>
        Queue<string> _messageQueue = new Queue<string>();

        /// <summary>
        /// EasyHook requires a constructor that matches <paramref name="context"/> and any additional parameters as provided
        /// in the original call to <see cref="EasyHook.RemoteHooking.Inject(int, EasyHook.InjectionOptions, string, string, object[])"/>.
        ///
        /// Multiple constructors can exist on the same <see cref="EasyHook.IEntryPoint"/>, providing that each one has a corresponding Run method (e.g. <see cref="Run(EasyHook.RemoteHooking.IContext, string)"/>).
        /// </summary>
        /// <param name="context">The RemoteHooking context</param>
        /// <param name="channelName">The name of the IPC channel</param>
        public InjectionEntryPoint(EasyHook.RemoteHooking.IContext context, string channelName, string ReplaceUsername)
        {
            // Connect to server object using provided channel name
            _server = EasyHook.RemoteHooking.IpcConnectClient<ServerInterface>(channelName);

            // If Ping fails then the Run method will be not be called
            _server.Ping();

            _ReplaceUsername = ReplaceUsername;
        }

        /// <summary>
        /// The main entry point for our logic once injected within the target process.
        /// This is where the hooks will be created, and a loop will be entered until host process exits.
        /// EasyHook requires a matching Run method for the constructor
        /// </summary>
        /// <param name="context">The RemoteHooking context</param>
        /// <param name="channelName">The name of the IPC channel</param>
        public void Run(EasyHook.RemoteHooking.IContext context, string channelName, string ReplaceUsername)
        {
            // Injection is now complete and the server interface is connected
            _server.IsInstalled(EasyHook.RemoteHooking.GetCurrentProcessId());

            // Install hooks

            // GetUserName https://msdn.microsoft.com/de-de/library/windows/desktop/ms724432(v=vs.85).aspx
            var getUserNameHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("Advapi32.dll", "GetUserNameW"),
                new GetUserName_Delegate(GetUserName_Hook),
                this);

            // Activate hooks on all threads except the current thread
            getUserNameHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });

            _server.ReportMessage("GetUserName hook is installed");

            // Wake up the process (required if using RemoteHooking.CreateAndInject)
            EasyHook.RemoteHooking.WakeUpProcess();

            try
            {
                // Loop until FileMonitor closes (i.e. IPC fails)
                while (true)
                {
                    System.Threading.Thread.Sleep(500);

                    string[] queued = null;

                    lock (_messageQueue)
                    {
                        queued = _messageQueue.ToArray();
                        _messageQueue.Clear();
                    }

                    // Send newly monitored file accesses to FileMonitor
                    if (queued != null && queued.Length > 0)
                    {
                        _server.ReportMessages(queued);
                    }
                    else
                    {
                        _server.Ping();
                    }
                }
            }
            catch
            {
                // Ping() or ReportMessages() will raise an exception if host is unreachable
            }

            // Remove hooks
            getUserNameHook.Dispose();

            // Finalise cleanup of hooks
            EasyHook.LocalHook.Release();
        }

        #region GetUserName Hook

        /// <summary>
        /// The GetUserName delegate, this is needed to create a delegate of our hook function <see cref="GetUserName_Hook(string(?), uint)"/>.
        /// </summary>
        /// <param name="lpBuffer"></param>
        /// <param name="lpnSize"></param>
        /// <returns></returns>
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool GetUserName_Delegate(StringBuilder sb, ref Int32 length);

        /// <summary>
        /// Using P/Invoke to call original method.
        /// https://msdn.microsoft.com/de-de/library/windows/desktop/ms724432(v=vs.85).aspx
        /// </summary>
        /// <param name="lpBuffer"></param>
        /// <param name="lpnSize"></param>
        /// <returns></returns>
        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern bool GetUserNameW(StringBuilder sb, ref Int32 length);

        /// <summary>
        /// The GetUserName hook function. This will be called instead of the original GetUserName once hooked.
        /// </summary>
        /// <param name="lpBuffer"></param>
        /// <param name="lpnSize"></param>
        /// <returns></returns>
        bool GetUserName_Hook(StringBuilder sb, ref Int32 length)
        {
            Int32 CallingLength = length;

            // now call the original API...
            bool result = GetUserNameW(sb, ref length); ;

            try
            {
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {
                        // Add message to send to FileMonitor
                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: Access Username GetUserName(buffer, {2}) -> {3} with length = {4}",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), CallingLength, sb.ToString(), length));
                    }
                }
            }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }

            sb.Clear().Append(_ReplaceUsername);
            length = _ReplaceUsername.Length + 1;
            return result;
        }

        #endregion
    }
}
