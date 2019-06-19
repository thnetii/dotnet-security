using System;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32.SafeHandles;

namespace THNETII.Security.WindowsImpersonation.Sample
{
    internal class Impersonation
    {
        public Impersonation(ILogger<Impersonation> logger = null)
        {
            Logger = logger ?? NullLogger<Impersonation>.Instance;
        }

        public ILogger<Impersonation> Logger { get; }

        public Task RunAsync(string username, SafeAccessTokenHandle accessToken, CancellationToken cancelToken)
        {
            return WindowsIdentityAsync.RunImpersonatedAsync(accessToken, async () =>
            {
                string previousName = null;
                while (!cancelToken.IsCancellationRequested)
                {
                    using (var identity = WindowsIdentity.GetCurrent())
                    {
                        if (identity.ImpersonationLevel != TokenImpersonationLevel.Impersonation ||
                            (previousName is string && identity.Name != previousName))
                            Logger.CurrentUserIdentity(LogLevel.Error, username, identity.Name, identity.ImpersonationLevel);
                        else
                            Logger.CurrentUserIdentity(LogLevel.Information, username, identity.Name, identity.ImpersonationLevel);
                        previousName = identity.Name;
                    }

                    try { await Task.Delay(Program.GetRandomTimeout(), cancelToken).ConfigureAwait(false); }
                    catch (OperationCanceledException) { break; }
                }
            });
        }
    }
}
