using Kentor.AuthServices.WebSso;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Configuration;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Security;

namespace Kentor.AuthServices.HttpModule
{
    /// <summary>
    /// Extension methods to CommandResult to update a HttpResponseBase.
    /// </summary>
    public static class CommandResultHttpExtension
    {
        /// <summary>
        /// Apply the command result to a bare HttpResponse.
        /// </summary>
        /// <param name="commandResult">The CommandResult that will update the HttpResponse.</param>
        /// <param name="response">Http Response to write the result to.</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "HttpStatusCode")]
        public static void Apply(this CommandResult commandResult, HttpResponseBase response)
        {
            if (commandResult == null)
            {
                throw new ArgumentNullException(nameof(commandResult));
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response));
            }

            response.Cache.SetCacheability((HttpCacheability)commandResult.Cacheability);

            ApplyCookies(commandResult, response);

            if (commandResult.HttpStatusCode == HttpStatusCode.SeeOther || commandResult.Location != null)
            {
                if (commandResult.Location == null)
                {
                    throw new InvalidOperationException("Missing Location on redirect.");
                }
                if (commandResult.HttpStatusCode != HttpStatusCode.SeeOther)
                {
                    throw new InvalidOperationException("Invalid HttpStatusCode for redirect, but Location is specified");
                }

                response.Redirect(commandResult.Location.OriginalString);
            }
            else
            {
                response.StatusCode = (int)commandResult.HttpStatusCode;
                response.ContentType = commandResult.ContentType;
                response.Write(commandResult.Content);

                response.End();
            }
        }

        /// <summary>
        /// Apply cookies of the CommandResult to the response.
        /// </summary>
        /// <param name="commandResult">Commandresult</param>
        /// <param name="response">Response</param>
        public static void ApplyCookies(this CommandResult commandResult, HttpResponseBase response)
        {
            if(commandResult == null)
            {
                throw new ArgumentNullException(nameof(commandResult));
            }

            if(response == null)
            {
                throw new ArgumentNullException(nameof(response));
            }

            if (!string.IsNullOrEmpty(commandResult.SetCookieName))
            {
                var protectedData = HttpRequestData.ConvertBinaryData(
                        MachineKey.Protect(
                            commandResult.GetSerializedRequestState(),
                            HttpRequestBaseExtensions.ProtectionPurpose));

                response.SetCookie(new HttpCookie(
                    commandResult.SetCookieName,
                    protectedData)
                {
                    HttpOnly = true
                });
            }

            if (!string.IsNullOrEmpty(commandResult.ClearCookieName))
            {
                response.SetCookie(new HttpCookie(commandResult.ClearCookieName)
                {
                    Expires = new DateTime(1970, 01, 01)
                });
            }
        }

        /// <summary>
        /// Establishes an application session by calling the session authentication module.
        /// </summary>
        [ExcludeFromCodeCoverage]
        public static void SignInOrOutSessionAuthenticationModule(this CommandResult commandResult)
        {
            if (commandResult == null)
            {
                throw new ArgumentNullException(nameof(commandResult));
            }

            // Ignore this if we're not running inside IIS, e.g. in unit tests.
            if (commandResult.Principal != null && HttpContext.Current != null)
            {
                var sessionToken = new SessionSecurityToken(
                    commandResult.Principal,
                    null,
                    DateTime.UtcNow,
                    commandResult.SessionNotOnOrAfter ??
                    CalculateSessionNotOnOrAfter())
                {
                    IsPersistent = true
                };

                EnsureSessionAuthenticationModuleAvailable();

                FederatedAuthentication.SessionAuthenticationModule
                    .AuthenticateSessionSecurityToken(sessionToken, true);
            }
            if (commandResult.TerminateLocalSession && HttpContext.Current != null)
            {
                EnsureSessionAuthenticationModuleAvailable();

                FederatedAuthentication.SessionAuthenticationModule.DeleteSessionTokenCookie();
            }
        }

        [ExcludeFromCodeCoverage]
        private static DateTime CalculateSessionNotOnOrAfter()
        {
            var configuredLifeTime = (FederatedAuthentication.FederationConfiguration
                    .IdentityConfiguration.SecurityTokenHandlers[typeof(SessionSecurityToken)]
                    as SessionSecurityTokenHandler).TokenLifetime;

            return DateTime.UtcNow.Add(configuredLifeTime);
        }

        [ExcludeFromCodeCoverage]
        [SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", Justification = "Several words in the GitHub link")]
        private static void EnsureSessionAuthenticationModuleAvailable()
        {
            if (FederatedAuthentication.SessionAuthenticationModule == null)
            {
                throw new InvalidOperationException(
                    "FederatedAuthentication.SessionAuthenticationModule is null, make sure you have loaded the SessionAuthenticationModule in web.config. " +
                    "See https://github.com/KentorIT/authservices/blob/master/doc/Configuration.md#loading-modules");
            }
        }
    }
}
