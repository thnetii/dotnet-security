using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Builder;
using System.CommandLine.Hosting;
using System.CommandLine.Invocation;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32.SafeHandles;
using THNETII.CommandLine.Extensions;

namespace THNETII.Security.WindowsImpersonation.Sample
{
    public static class Program
    {
        private static readonly Option UsernameOption = new Option(new[] { "--user", "-u" })
        {
            Description = "One or more usernames to impersonate",
            Argument = new Argument<string[]>("USERNAME")
            {
                Arity = ArgumentArity.ZeroOrMore,
            }
        };

        private static readonly Option PasswordOption = new Option(new[] { "--password", "-p" })
        {
            Description = "Passwords for users. Must be in format '<n>:<password>' where <n> is the 1-based index into the list of usernames",
            Argument = new Argument<Dictionary<int, string>>(ConvertPasswordValueToKvp)
            {
                Name = "PASSWORDS",
                Arity = ArgumentArity.ZeroOrMore,
            }
        };

        private static bool ConvertPasswordValueToKvp(SymbolResult result, out Dictionary<int, string> dict)
        {
            bool isSuccess = true;
            dict = result.Tokens.Select(v =>
            {
                if (v.Type != TokenType.Argument)
                    isSuccess = false;
                var parts = v.Value.Split(':', count: 2);
                int n = 0;
                string pwd = null;
                if (parts.Length > 0)
                {
                    if (!int.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out n))
                        isSuccess = false;
                }
                if (parts.Length > 1)
                    pwd = parts[1];

                // Subtract 1 from n to make index 0-based
                return (key: n - 1, value: pwd);
            }).ToDictionary(t => t.key, t => t.value);
            return isSuccess;
        }

        public static Task Main(string[] args)
        {
            var parser = new CommandLineBuilder(
                new RootCommand
                {
                    Handler = CommandHandler.Create<IHost, ParseResult, CancellationToken>(RunAsync)
                })
                .AddOption(UsernameOption)
                .AddOption(PasswordOption)
                .UseDefaults()
                .UseHost(Host.CreateDefaultBuilder, ConfigureHost)
                .Build();

            return parser.InvokeAsync(args);
        }

        private static async Task RunAsync(IHost host, ParseResult parseResult, CancellationToken cancelToken)
        {
            const string domain = ".";

            var logger = host.Services.GetRequiredService<ILoggerFactory>()
                .CreateLogger(typeof(Program)) ?? NullLogger.Instance;

            var usernames = parseResult.FindResultFor(UsernameOption).GetValueOrDefault<string[]>() ?? Array.Empty<string>();
            var passwords = parseResult.FindResultFor(PasswordOption)?.GetValueOrDefault<Dictionary<int, string>>() ?? new Dictionary<int, string>();
            var credentials = usernames
                .Select((username, index) =>
                {
                    _ = passwords.TryGetValue(index, out string password);
                    return (username, password);
                })
                .Select(creds =>
                {
                    if (cancelToken.IsCancellationRequested)
                        return default;
                    var (username, passwordString) = creds;
                    bool loggedIn = false;
                    int authError = 0;
                    SafeAccessTokenHandle accessToken = null;
                    if (passwordString is string)
                    {
                        if (cancelToken.IsCancellationRequested)
                            return default;
                        loggedIn = NativeMethods.LogonUser(
                            username, domain, passwordString,
                            NativeMethods.LogonType.LOGON32_LOGON_INTERACTIVE,
                            NativeMethods.LogonProvider.LOGON32_PROVIDER_DEFAULT,
                            out accessToken);
                        if (!loggedIn)
                        {
                            authError = Marshal.GetLastWin32Error();
                            logger.Win32NativeFuncResult(LogLevel.Warning, authError, nameof(NativeMethods.LogonUser), username);
                        }
                    }

                    const int defaultLength = 64;
                    var usernameBuilder = new StringBuilder(username ?? string.Empty, defaultLength);
                    var passwordBuilder = new StringBuilder(passwordString, defaultLength);
                    while (!loggedIn)
                    {
                        if (cancelToken.IsCancellationRequested)
                            return default;
                        int save = 0;
                        int promptResult = NativeMethods.CredUICmdLinePromptForCredentials(
                            Environment.MachineName, IntPtr.Zero, authError,
                            usernameBuilder, usernameBuilder.Capacity,
                            passwordBuilder, passwordBuilder.Capacity,
                            ref save,
                            NativeMethods.CredUiFlags.CREDUI_FLAGS_ALWAYS_SHOW_UI |
                            NativeMethods.CredUiFlags.CREDUI_FLAGS_DO_NOT_PERSIST |
                            NativeMethods.CredUiFlags.CREDUI_FLAGS_EXCLUDE_CERTIFICATES |
                            NativeMethods.CredUiFlags.CREDUI_FLAGS_GENERIC_CREDENTIALS);
                        if (promptResult != 0)
                        {
                            logger.Win32NativeFuncResult(LogLevel.Critical, promptResult, nameof(NativeMethods.CredUICmdLinePromptForCredentials), username);
                            return (username, null);
                        }

                        if (cancelToken.IsCancellationRequested)
                            return default;
                        loggedIn = NativeMethods.LogonUser(
                            usernameBuilder, domain, passwordBuilder,
                            NativeMethods.LogonType.LOGON32_LOGON_INTERACTIVE,
                            NativeMethods.LogonProvider.LOGON32_PROVIDER_DEFAULT,
                            out accessToken);
                        if (!loggedIn)
                        {
                            authError = Marshal.GetLastWin32Error();
                            var except = new Win32Exception(authError);
                            logger.Win32NativeFuncResult(LogLevel.Error, authError, nameof(NativeMethods.LogonUser), usernameBuilder.ToString());
                        }
                    }

                    username = usernameBuilder.ToString();
                    logger.LogInformation($"{nameof(NativeMethods.LogonUser)}('{{{nameof(username)}}}'): Successfully logged in", username);

                    usernameBuilder.Clear();
                    passwordBuilder.Clear();

                    return (username, accessToken);
                })
                .Where(t => t.accessToken is SafeAccessTokenHandle).ToList();

            if (cancelToken.IsCancellationRequested)
                return;

            var currentUser = host.Services.GetRequiredService<CurrentUser>();
            var impersonationTasks = credentials.Select(creds =>
            {
                var (username, accessToken) = creds;
                var imp = host.Services.GetRequiredService<Impersonation>();
                return imp.RunAsync(username, accessToken, cancelToken);
            }).ToList();

            if (cancelToken.IsCancellationRequested)
                return;

            await currentUser.RunAsync(cancelToken).ConfigureAwait(false);
            await Task.WhenAll(impersonationTasks).ConfigureAwait(false);

            foreach (var (_, token) in credentials)
                token?.Dispose();
        }

        private static void ConfigureHost(IHostBuilder host)
        {
            host.ConfigureHostConfiguration(config =>
            {
                config.AddUserSecrets(typeof(Program).Assembly, optional: true, reloadOnChange: true);
            });
            host.ConfigureServices(ConfigureServices);
        }

        private static void ConfigureServices(HostBuilderContext hostingContext, IServiceCollection services)
        {
            services.AddTransient<CurrentUser>();
            services.AddTransient<Impersonation>();
        }

        private static readonly Random randomizer = new Random();

        internal static TimeSpan GetRandomTimeout()
            => TimeSpan.FromMilliseconds(randomizer.Next(50, 2_000));
    }
}
