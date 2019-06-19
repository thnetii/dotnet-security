using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace THNETII.Security.WindowsImpersonation.Sample
{
    internal static class NativeMethods
    {
        internal const string Advapi32 = "Advapi32.dll";
        internal const string Credui = "Credui.dll";

        public enum LogonType
        {
            /// <summary>
            /// This logon type is intended for users who will be interactively using the computer, such as a user being logged on  
            /// by a terminal server, remote shell, or similar process.
            /// This logon type has the additional expense of caching logon information for disconnected operations;
            /// therefore, it is inappropriate for some client/server applications,
            /// such as a mail server.
            /// </summary>
            LOGON32_LOGON_INTERACTIVE = 2,

            /// <summary>
            /// This logon type is intended for high performance servers to authenticate plaintext passwords.

            /// The LogonUser function does not cache credentials for this logon type.
            /// </summary>
            LOGON32_LOGON_NETWORK = 3,

            /// <summary>
            /// This logon type is intended for batch servers, where processes may be executing on behalf of a user without
            /// their direct intervention. This type is also for higher performance servers that process many plaintext
            /// authentication attempts at a time, such as mail or Web servers.
            /// The LogonUser function does not cache credentials for this logon type.
            /// </summary>
            LOGON32_LOGON_BATCH = 4,

            /// <summary>
            /// Indicates a service-type logon. The account provided must have the service privilege enabled.
            /// </summary>
            LOGON32_LOGON_SERVICE = 5,

            /// <summary>
            /// This logon type is for GINA DLLs that log on users who will be interactively using the computer.
            /// This logon type can generate a unique audit record that shows when the workstation was unlocked.
            /// </summary>
            LOGON32_LOGON_UNLOCK = 7,

            /// <summary>
            /// This logon type preserves the name and password in the authentication package, which allows the server to make
            /// connections to other network servers while impersonating the client. A server can accept plaintext credentials
            /// from a client, call LogonUser, verify that the user can access the system across the network, and still
            /// communicate with other servers.
            /// NOTE: Windows NT:  This value is not supported.
            /// </summary>
            LOGON32_LOGON_NETWORK_CLEARTEXT = 8,

            /// <summary>
            /// This logon type allows the caller to clone its current token and specify new credentials for outbound connections.
            /// The new logon session has the same local identifier but uses different credentials for other network connections.
            /// NOTE: This logon type is supported only by the LOGON32_PROVIDER_WINNT50 logon provider.
            /// NOTE: Windows NT:  This value is not supported.
            /// </summary>
            LOGON32_LOGON_NEW_CREDENTIALS = 9,
        }

        public enum LogonProvider
        {
            /// <summary>
            /// Use the standard logon provider for the system.
            /// The default security provider is negotiate, unless you pass NULL for the domain name and the user name
            /// is not in UPN format. In this case, the default provider is NTLM.
            /// NOTE: Windows 2000/NT:   The default security provider is NTLM.
            /// </summary>
            LOGON32_PROVIDER_DEFAULT = 0,
            LOGON32_PROVIDER_WINNT35 = 1,
            LOGON32_PROVIDER_WINNT40 = 2,
            LOGON32_PROVIDER_WINNT50 = 3
        }

        [Flags]
        public enum CredUiFlags
        {
            CREDUI_FLAGS_INCORRECT_PASSWORD = 0x00001,
            CREDUI_FLAGS_DO_NOT_PERSIST = 0x00002,
            CREDUI_FLAGS_REQUEST_ADMINISTRATOR = 0x00004,
            CREDUI_FLAGS_EXCLUDE_CERTIFICATES = 0x00008,
            CREDUI_FLAGS_REQUIRE_CERTIFICATE = 0x00010,
            CREDUI_FLAGS_SHOW_SAVE_CHECK_BOX = 0x00040,
            CREDUI_FLAGS_ALWAYS_SHOW_UI = 0x00080,
            CREDUI_FLAGS_REQUIRE_SMARTCARD = 0x00100,
            CREDUI_FLAGS_PASSWORD_ONLY_OK = 0x00200,
            CREDUI_FLAGS_VALIDATE_USERNAME = 0x00400,
            CREDUI_FLAGS_COMPLETE_USERNAME = 0x00800,
            CREDUI_FLAGS_PERSIST = 0x01000,
            CREDUI_FLAGS_SERVER_CREDENTIAL = 0x04000,
            CREDUI_FLAGS_EXPECT_CONFIRMATION = 0x20000,
            CREDUI_FLAGS_GENERIC_CREDENTIALS = 0x40000,
            CREDUI_FLAGS_USERNAME_TARGET_CREDENTIALS = 0x80000,
            CREDUI_FLAGS_KEEP_USERNAME = 0x100000,
        }

        [DllImport(Advapi32, CallingConvention = CallingConvention.Winapi, EntryPoint = nameof(LogonUser) + "W", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern unsafe bool LogonUser(
            [MarshalAs(UnmanagedType.LPWStr)] string username,
            [MarshalAs(UnmanagedType.LPWStr), Optional] string domain,
            [MarshalAs(UnmanagedType.LPWStr)] string  password,
            [MarshalAs(UnmanagedType.I4)] LogonType logonType,
            [MarshalAs(UnmanagedType.I4)] LogonProvider logonProvider,
            out SafeAccessTokenHandle token
            );

        [DllImport(Advapi32, CallingConvention = CallingConvention.Winapi, EntryPoint = nameof(LogonUser) + "W", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern unsafe bool LogonUser(
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder username,
            [MarshalAs(UnmanagedType.LPWStr), Optional] string domain,
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder password,
            [MarshalAs(UnmanagedType.I4)] LogonType logonType,
            [MarshalAs(UnmanagedType.I4)] LogonProvider logonProvider,
            out SafeAccessTokenHandle token
            );

        [DllImport(Credui, CallingConvention = CallingConvention.Winapi, EntryPoint = nameof(CredUICmdLinePromptForCredentials) + "W")]
        public static extern unsafe int CredUICmdLinePromptForCredentials(
            [MarshalAs(UnmanagedType.LPWStr)] string targetName,
            IntPtr context,
            int authError,
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder userName,
            int userBufferSize,
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder password,
            int passwordBufferSize,
            ref int save,
            [MarshalAs(UnmanagedType.I4)] CredUiFlags flags = default
            );
    }
}
