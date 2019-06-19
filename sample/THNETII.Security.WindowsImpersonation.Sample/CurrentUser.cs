using System;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace THNETII.Security.WindowsImpersonation.Sample
{
    internal class CurrentUser
    {
        public CurrentUser(ILogger<CurrentUser> logger = null)
        {
            Logger = logger ?? NullLogger<CurrentUser>.Instance;
            using (var identity = WindowsIdentity.GetCurrent())
            {
                OriginalName = identity.Name;
            }
        }

        public ILogger<CurrentUser> Logger { get; }
        public string OriginalName { get; }

        public async Task RunAsync(CancellationToken cancelToken)
        {
            while (!cancelToken.IsCancellationRequested)
            {
                using (var identity = WindowsIdentity.GetCurrent())
                {
                    if (identity.ImpersonationLevel != TokenImpersonationLevel.None ||
                        identity.Name != OriginalName)
                        Logger.CurrentUserIdentity(LogLevel.Error, OriginalName, identity.Name, identity.ImpersonationLevel);
                    else
                        Logger.CurrentUserIdentity(LogLevel.Information, OriginalName, identity.Name, identity.ImpersonationLevel);
                }

                try { await Task.Delay(Program.GetRandomTimeout(), cancelToken).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }
    }
}
