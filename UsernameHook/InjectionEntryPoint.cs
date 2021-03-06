﻿using System;
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
        private ServerInterface _server = null;

        /// <summary>
        /// Stores the Username, that will be returned to every calling process
        /// </summary>
        private string _ReplaceUsername;

        /// <summary>
        /// Stores the Domain Name, that will be returned to every calling process
        /// </summary>
        private string _ReplaceDomainName;

        /// <summary>
        /// Message queue of all files accessed
        /// </summary>
        private Queue<string> _messageQueue = new Queue<string>();

        /// <summary>
        /// EasyHook requires a constructor that matches <paramref name="context"/> and any additional parameters as provided
        /// in the original call to <see cref="EasyHook.RemoteHooking.Inject(int, EasyHook.InjectionOptions, string, string, object[])"/>.
        ///
        /// Multiple constructors can exist on the same <see cref="EasyHook.IEntryPoint"/>, providing that each one has a corresponding Run method (e.g. <see cref="Run(EasyHook.RemoteHooking.IContext, string)"/>).
        /// </summary>
        /// <param name="context">The RemoteHooking context</param>
        /// <param name="channelName">The name of the IPC channel</param>
        public InjectionEntryPoint(EasyHook.RemoteHooking.IContext context, string channelName, string ReplaceUsername, string ReplaceDomainName)
        {
            // Connect to server object using provided channel name
            _server = EasyHook.RemoteHooking.IpcConnectClient<ServerInterface>(channelName);

            // If Ping fails then the Run method will be not be called
            _server.Ping();

            _ReplaceUsername = ReplaceUsername;
            _ReplaceDomainName = ReplaceDomainName;
        }

        /// <summary>
        /// The main entry point for our logic once injected within the target process.
        /// This is where the hooks will be created, and a loop will be entered until host process exits.
        /// EasyHook requires a matching Run method for the constructor
        /// </summary>
        /// <param name="context">The RemoteHooking context</param>
        /// <param name="channelName">The name of the IPC channel</param>
        public void Run(EasyHook.RemoteHooking.IContext context, string channelName, string ReplaceUsername, string ReplaceDomainName)
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

            // LookupAccountName https://msdn.microsoft.com/de-de/library/windows/desktop/aa379159(v=vs.85).aspx
            var lookupAccountNameHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("Advapi32.dll", "LookupAccountNameW"),
                new LookupAccountName_Delegate(lookupAccountName_Hook),
                this);

            // Activate hooks on all threads except the current thread
            lookupAccountNameHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });

            _server.ReportMessage("LookupAccountNameHook hook is installed");

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
            lookupAccountNameHook.Dispose();

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

        #region LookupAccountName Hook

        /// <summary>
        /// See https://msdn.microsoft.com/de-de/library/windows/desktop/aa379601(v=vs.85).aspx
        /// </summary>
        enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }

        /// <summary>
        /// The LookupAccountName delegate, this is needed to create a delegate of our hook function <see cref="lookupAccountName_Hook(...)"/>.
        /// </summary>
        /// <returns></returns>
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool LookupAccountName_Delegate(string lpSystemName, string lpAccountName, [MarshalAs(UnmanagedType.LPArray)] byte[] Sid, ref uint cbSid, StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out SID_NAME_USE peUse);

        /// <summary>
        /// Using P/Invoke to call original method.
        /// https://msdn.microsoft.com/de-de/library/windows/desktop/aa379159(v=vs.85).aspx
        /// </summary>
        /// <param name="lpBuffer"></param>
        /// <param name="lpnSize"></param>
        /// <returns></returns>
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool LookupAccountName(string lpSystemName, string lpAccountName, [MarshalAs(UnmanagedType.LPArray)] byte[] Sid, ref uint cbSid, StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out SID_NAME_USE peUse);


        /// <summary>
        /// The LookupAccountName hook function. This will be called instead of the original LookupAccountName once hooked.
        /// </summary>
        /// <returns></returns>
        bool lookupAccountName_Hook(string lpSystemName, string lpAccountName, [MarshalAs(UnmanagedType.LPArray)] byte[] Sid, ref uint cbSid, StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out SID_NAME_USE peUse)
        {
            bool result;
            // Filter for the correct calling type
            if (lpSystemName == null)
            {
                // Hook if SystemName is null
                peUse = SID_NAME_USE.SidTypeUser;
                ReferencedDomainName.Clear().Append(_ReplaceDomainName);
                result = true;

            }
            else
            {
                // now call the original API...
                result = LookupAccountName(lpSystemName, lpAccountName, Sid, ref cbSid, ReferencedDomainName, ref cchReferencedDomainName, out peUse);
            }

            try
            {
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {
                        // Add message to send to FileMonitor
                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: Access LookupAccountName for account {2} -> {3}",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), lpAccountName, ReferencedDomainName.ToString()));
                    }
                }
            }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }



            return result;
        }
    }
    #endregion
}
