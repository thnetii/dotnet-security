using System;
using System.ComponentModel;
using System.Security.Principal;
using Microsoft.Extensions.Logging;

namespace THNETII.Security.WindowsImpersonation.Sample
{
    internal static class LoggingExtensions
    {
        public static void Win32NativeFuncResult(this ILogger logger, LogLevel logLevel, int statusCode, string function, string argument)
        {
            var except = new Win32Exception(statusCode);
            var message = except.Message;
            logger.Log(logLevel, statusCode, $"{{{nameof(function)}}}({{{nameof(argument)}}}) -> {{{nameof(message)}}} ({{{nameof(statusCode)}}})", function, argument, message, $"0x{statusCode:X8}");
        }

        public static void CurrentUserIdentity(this ILogger logger, LogLevel logLevel, string originalName, string currentName, TokenImpersonationLevel impersonationLevel)
        {
            logger.Log(logLevel, $"OriginalName = {{{nameof(originalName)}}}, CurrentName = {{{nameof(currentName)}}}, Impersonation = {{{nameof(impersonationLevel)}}}", originalName, currentName, impersonationLevel);
        }
    }
}
