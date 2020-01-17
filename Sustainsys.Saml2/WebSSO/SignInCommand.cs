using Sustainsys.Saml2.Configuration;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using Sustainsys.Saml2.Internal;
using Sustainsys.Saml2.Metadata;

namespace Sustainsys.Saml2.WebSso
{
    /// <summary>
    /// Represents the sign in command behaviour.
    /// Instances of this class can be created directly or by using the factory method
    /// CommandFactory.GetCommand(CommandFactory.SignInCommandName).
    /// </summary>
    public class SignInCommand : ICommand
    {
        /// <summary>
        /// Run the command, initiating the sign in sequence.
        /// </summary>
        /// <param name="request">Request data.</param>
        /// <param name="options">Options</param>
        /// <returns>CommandResult</returns>
        public CommandResult Run(HttpRequestData request, IOptions options)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            var returnUrl = GetReturnUrl(request, options);

            var result = Run(
                new EntityId(request.QueryString["idp"].FirstOrDefault()),
                returnUrl,
                request,
                options,
                request.StoredRequestState?.RelayData);

            if (request.RelayState != null)
            {
                result.ClearCookieName = StoredRequestState.CookieNameBase + request.RelayState;
            }

            return result;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "SignIn")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "RelayState")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "ReturnUrl")]
        private static string GetReturnUrl(HttpRequestData request, IOptions options)
        {
            var returnUrl = request.QueryString["ReturnUrl"].FirstOrDefault();
            if (returnUrl != null)
            {
                if (request.RelayState != null)
                {
                    throw new InvalidOperationException("Both a ReturnUrl and a RelayState query " +
                        "string parameter found in call to SignIn. That is not allowed. If a " +
                        "RelayState is found the call is a response to a discovery service request. " +
                        "The ReturnUrl has been added erroneously by the discovery service.");
                }

                options.SPOptions.Logger.WriteVerbose("Extracted ReturnUrl " + returnUrl + " from query string");
                if (!PathHelper.IsLocalWebUrl(returnUrl))
                {
                    if (!options.Notifications.ValidateAbsoluteReturnUrl(returnUrl))
                    {
                        throw new InvalidOperationException("Return Url must be a relative Url.");
                    }
                }
            }

            if (request.StoredRequestState != null)
            {
                returnUrl = request.StoredRequestState.ReturnUrl?.OriginalString;
            }

            return returnUrl;
        }

        /// <summary>
        /// Initiate the sign in sequence.
        /// </summary>
        /// <param name="idpEntityId">Entity id of idp to sign in to, or
        /// null to use default (discovery service if configured)</param>
        /// <param name="returnPath">Path to redirect to when the sign in
        /// is complete.</param>
        /// <param name="request">The incoming http request.</param>
        /// <param name="options">Options.</param>
        /// <param name="relayData">Data to store and make available when the
        /// ACS command has processed the response.</param>
        /// <returns>Command Result</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2234:PassSystemUriObjectsInsteadOfStrings")]
        public static CommandResult Run(
            EntityId idpEntityId,
            string returnPath,
            HttpRequestData request,
            IOptions options,
            IDictionary<string, string> relayData)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            var urls = new Saml2Urls(request, options);
            if (!string.IsNullOrEmpty(returnPath))
            {
                returnPath = options.Notifications.RewriteRedirectUrl(new Uri(returnPath, UriKind.RelativeOrAbsolute), urls.ApplicationUrl).ToString();
            }

            IdentityProvider idp = options.Notifications.SelectIdentityProvider(idpEntityId, relayData);
            if (idp == null)
            {
                var idpEntityIdString = idpEntityId?.Id;
                if (idpEntityIdString == null)
                {
                    if (options.SPOptions.DiscoveryServiceUrl != null)
                    {
                        var commandResult = RedirectToDiscoveryService(returnPath, options.SPOptions, urls, relayData);
                        options.Notifications.SignInCommandResultCreated(commandResult, relayData);
                        options.SPOptions.Logger.WriteInformation("Redirecting to Discovery Service to select Idp.");
                        return commandResult;
                    }
                    idp = options.IdentityProviders.Default;
                    options.SPOptions.Logger.WriteVerbose(
                        "No specific idp requested and no Discovery Service configured. " +
                        "Falling back to use configured default Idp " + idp.EntityId.Id);
                }
                else
                {
                    if (!options.IdentityProviders.TryGetValue(idpEntityId, out idp))
                    {
                        throw new InvalidOperationException("Unknown idp " + idpEntityIdString);
                    }
                }
            }

            var returnUrl = string.IsNullOrEmpty(returnPath)
                ? null
                : new Uri(returnPath, UriKind.RelativeOrAbsolute);

            options.SPOptions.Logger.WriteInformation("Initiating login to " + idp.EntityId.Id);
            return InitiateLoginToIdp(options, relayData, urls, idp, returnUrl);
        }

        private static CommandResult InitiateLoginToIdp(IOptions options, IDictionary<string, string> relayData, Saml2Urls urls, IdentityProvider idp, Uri returnUrl)
        {
            var authnRequest = idp.CreateAuthenticateRequest(urls);

            options.Notifications.AuthenticationRequestCreated(authnRequest, idp, relayData);

            var commandResult = idp.Bind(authnRequest);

            commandResult.RequestState = new StoredRequestState(
                idp.EntityId, returnUrl, authnRequest.Id, relayData);

            commandResult.SetCookieSecureFlag = urls.AssertionConsumerServiceUrl.IsHttps();
            commandResult.SetCookieName = StoredRequestState.CookieNameBase + authnRequest.RelayState;

            options.Notifications.SignInCommandResultCreated(commandResult, relayData);

            return commandResult;
        }

        private static CommandResult RedirectToDiscoveryService(
            string returnPath,
            SPOptions spOptions,
            Saml2Urls saml2Urls,
            IDictionary<string, string> relayData)
        {
            string returnUrl = saml2Urls.SignInUrl.OriginalString;

            var relayState = SecureKeyGenerator.CreateRelayState();

            returnUrl += "?RelayState=" + Uri.EscapeDataString(relayState);

            var redirectLocation = string.Format(
                CultureInfo.InvariantCulture,
                "{0}?entityID={1}&return={2}&returnIDParam=idp",
                spOptions.DiscoveryServiceUrl,
                Uri.EscapeDataString(spOptions.EntityId.Id),
                Uri.EscapeDataString(returnUrl));

            var requestState = new StoredRequestState(
                null,
                returnPath == null ? null : new Uri(returnPath, UriKind.RelativeOrAbsolute),
                null,
                relayData);

            return new CommandResult()
            {
                HttpStatusCode = HttpStatusCode.SeeOther,
                Location = new Uri(redirectLocation),
                RequestState = requestState,
                SetCookieName = StoredRequestState.CookieNameBase + relayState,
                SetCookieSecureFlag = saml2Urls.AssertionConsumerServiceUrl.IsHttps()
            };
        }
    }
}
