using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Principal;
using System.Threading.Tasks;

using Microsoft.Win32.SafeHandles;

namespace THNETII.Security.WindowsImpersonation
{
    [SuppressMessage("Usage", "PC001: API not supported on all platforms", Justification = "Windows-only API")]
    public static class WindowsIdentityAsync
    {
        private static readonly WindowsImpersonationTaskScheduler taskScheduler =
            new WindowsImpersonationTaskScheduler();
        private static readonly TaskFactory taskFactory = new TaskFactory(taskScheduler);

        private static class TypedHelper<T>
        {
            public static readonly TaskFactory<T> taskFactory = new TaskFactory<T>(taskScheduler);
        }

        private class ImpersonationTaskArguments
        {
            public SafeAccessTokenHandle Token { get; set; }
            public Func<Task> AsyncAction { get; set; }

            public void Deconstruct(out SafeAccessTokenHandle token, out Func<Task> action)
                => (token, action) = (Token, AsyncAction);
        }

        private class ImpersonationTaskArguments<T>
        {
            public SafeAccessTokenHandle Token { get; set; }
            public Func<Task<T>> AsyncAction { get; set; }

            public void Deconstruct(out SafeAccessTokenHandle token, out Func<Task<T>> action)
                => (token, action) = (Token, AsyncAction);
        }

        public static Task RunImpersonatedAsync(SafeAccessTokenHandle token, Func<Task> asyncAction)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            if (asyncAction is null)
            {
                throw new ArgumentNullException(nameof(asyncAction));
            }

            return taskFactory.StartNew(
                ImpersonatedTaskEntryPoint,
                new ImpersonationTaskArguments
                {
                    Token = token,
                    AsyncAction = asyncAction
                },
                default, TaskCreationOptions.LongRunning, taskScheduler);
        }

        public static Task<T> RunImpersonatedAsync<T>(SafeAccessTokenHandle token, Func<Task<T>> asyncAction)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            if (asyncAction is null)
            {
                throw new ArgumentNullException(nameof(asyncAction));
            }

            return TypedHelper<T>.taskFactory.StartNew(
                ImpersonatedTaskEntryPoint<T>,
                new ImpersonationTaskArguments<T>
                {
                    Token = token,
                    AsyncAction = asyncAction
                },
                default, TaskCreationOptions.LongRunning, taskScheduler);
        }

        private static void ImpersonatedTaskEntryPoint(object state)
        {
            var args = (ImpersonationTaskArguments)state;
            var (token, asyncAction) = args;

            WindowsIdentity.RunImpersonated(token, () =>
            {
                asyncAction().GetAwaiter().GetResult();
            });
        }

        private static T ImpersonatedTaskEntryPoint<T>(object state)
        {
            var args = (ImpersonationTaskArguments<T>)state;
            var (token, asyncAction) = args;

            return WindowsIdentity.RunImpersonated(token, () =>
            {
                return asyncAction().GetAwaiter().GetResult();
            });
        }
    }
}
