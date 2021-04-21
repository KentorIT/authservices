using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Sustainsys.Saml2.Metadata;
using Sustainsys.Saml2.Owin.Extensions;
using Sustainsys.Saml2.WebSso;

namespace Sustainsys.Saml2.Owin
{
    class Saml2AuthenticationHandler : AuthenticationHandler<Saml2AuthenticationOptions>
    {
        protected async override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            var acsPath = new PathString(Options.SPOptions.ModulePath)
                .Add(new PathString("/" + CommandFactory.AcsCommandName));

            if (Request.Path != acsPath)
            {
                return null;
            }

            var httpRequestData = await Context.ToHttpRequestData(Options.CookieManager, Options.DataProtector.Unprotect);
            try
            {
                var result = CommandFactory.GetCommand(CommandFactory.AcsCommandName)
                    .Run(httpRequestData, Options);

                if (!result.HandledResult)
                {
                    result.Apply(
                        Context,
                        Options.DataProtector,
                        Options.CookieManager,
                        Options.Notifications.EmitSameSiteNone(Request.GetUserAgent()));
                }

                var identities = result.Principal.Identities.Select(i =>
                    new ClaimsIdentity(i, null, Options.SignInAsAuthenticationType, i.NameClaimType, i.RoleClaimType));

                var authProperties = new AuthenticationProperties(result.RelayData)
                {
                    RedirectUri = result.Location.OriginalString
                };
                if (result.SessionNotOnOrAfter.HasValue)
                {
                    authProperties.AllowRefresh = false;
                    authProperties.ExpiresUtc = result.SessionNotOnOrAfter.Value;
                }

                return new MultipleIdentityAuthenticationTicket(identities, authProperties);
            }
            catch (Exception ex)
            {
                return CreateErrorAuthenticationTicket(httpRequestData, ex);
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "SPOptions")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "ReturnUrl")]
        private AuthenticationTicket CreateErrorAuthenticationTicket(HttpRequestData httpRequestData, Exception ex)
        {
            var authProperties = new AuthenticationProperties();

            if (httpRequestData.StoredRequestState?.ReturnUrl != null)
            {
                // ReturnUrl is removed from AuthProps dictionary to save space, need to put it back.
                authProperties.RedirectUri = httpRequestData.StoredRequestState.ReturnUrl.OriginalString;
            }
            else
            {
                var redirectUrl = Options.SPOptions.ReturnUrl;

                if (redirectUrl == null)
                {
                    Options.SPOptions.Logger.WriteError(
                        "An error occurred and no request state with a return url is available. " +
                        "The fallback behavior is to redirect to the location configured in " +
                        "SPOptions.ReturnUrl. However, that is null so a redirect is done to the " +
                        "application root instead.", null);

                    redirectUrl = httpRequestData.ApplicationUrl;
                }
                authProperties.RedirectUri = redirectUrl.OriginalString;
            }

            // The Google middleware adds this, so let's follow that example.
            authProperties.RedirectUri = WebUtilities.AddQueryString(
                authProperties.RedirectUri, "error", "access_denied");

            string samlResponse = ex.Data.Contains("Saml2Response")
                ? " The received SAML data is\n" + ex.Data["Saml2Response"]
                : "";

            Options.SPOptions.Logger.WriteError("Saml2 Authentication failed." + samlResponse, ex);
            return new MultipleIdentityAuthenticationTicket(
                Enumerable.Empty<ClaimsIdentity>(),
                authProperties);
        }

        protected override async Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode == 401)
            {
                var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

                if (challenge != null)
                {
                    EntityId idp;
                    if (challenge.Properties.Dictionary.TryGetValue("idp", out string strIdp))
                    {
                        idp = new EntityId(strIdp);
                    }
                    else
                    {
                        Context.Environment.TryGetValue("saml2.idp", out object objIdp);
                        idp = objIdp as EntityId;
                    }
                    var redirectUri = challenge.Properties.RedirectUri;
                    // Don't serialize the RedirectUri twice.
                    challenge.Properties.RedirectUri = null;

                    if (redirectUri == null)
                    {
                        redirectUri = Context.Request.Uri.ToString();
                    }

                    var result = SignInCommand.Run(
                        idp,
                        redirectUri,
                        await Context.ToHttpRequestData(Options.CookieManager, Options.DataProtector.Unprotect),
                        Options,
                        challenge.Properties.Dictionary);

                    if (!result.HandledResult)
                    {
                        result.Apply(
                            Context,
                            Options.DataProtector,
                            Options.CookieManager,
                            Options.Notifications.EmitSameSiteNone(Request.GetUserAgent()));
                    }
                }
            }
        }

        protected async override Task ApplyResponseGrantAsync()
        {
            // Automatically sign out, even if passive because passive sign in and auto sign out
            // is typically most common scenario. Unless strict compatibility is set.
            var mode = Options.SPOptions.Compatibility.StrictOwinAuthenticationMode ?
                Options.AuthenticationMode : AuthenticationMode.Active;

            var revoke = Helper.LookupSignOut(Options.AuthenticationType, mode);

            if (revoke != null && Context.Request.Path.Value != (Options.SPOptions.ModulePath + "/Logout"))
            {
                var request = await Context.ToHttpRequestData(Options.CookieManager, Options.DataProtector.Unprotect);
                var urls = new Saml2Urls(request, Options);

                string redirectUrl = revoke.Properties.RedirectUri;
                if (string.IsNullOrEmpty(redirectUrl))
                {
                    if (Context.Response.StatusCode / 100 == 3)
                    {
                        redirectUrl = Context.Response.Headers["Location"];
                    }
                    else
                    {
                        // ApplicationUrl is base path, after consideration taken to PublicOrigin.
                        redirectUrl = urls.ApplicationUrl.AbsolutePath + Context.Request.Path.ToString().TrimStart('/');
                    }
                }

                var result = LogoutCommand.Run(request, redirectUrl, Options);

                if (!result.HandledResult)
                {
                    result.Apply(
                        Context,
                        Options.DataProtector,
                        Options.CookieManager,
                        Options.Notifications.EmitSameSiteNone(Request.GetUserAgent()));
                }
            }

            await AugmentAuthenticationGrantWithLogoutClaims(Context);
        }

        public override async Task<bool> InvokeAsync()
        {
            var Saml2Path = new PathString(Options.SPOptions.ModulePath);

            if (Request.Path.StartsWithSegments(Saml2Path, StringComparison.OrdinalIgnoreCase, out PathString remainingPath))
            {
                if (remainingPath == new PathString("/" + CommandFactory.AcsCommandName))
                {
                    var ticket = (MultipleIdentityAuthenticationTicket)await AuthenticateAsync();
                    if (ticket.Identities.Any())
                    {
                        Context.Authentication.SignIn(ticket.Properties, ticket.Identities.ToArray());
                        // No need to redirect here. Command result is applied in AuthenticateCoreAsync.
                    }
                    else
                    {
                        Response.Redirect(ticket.Properties.RedirectUri);
                    }
                    return true;
                }

                try
                {
                    var result = CommandFactory.GetCommand(remainingPath.Value)
                        .Run(await Context.ToHttpRequestData(Options.CookieManager, Options.DataProtector.Unprotect), Options);

                    if (!result.HandledResult)
                    {
                        result.Apply(
                            Context,
                            Options.DataProtector,
                            Options.CookieManager,
                            Options.Notifications.EmitSameSiteNone(Request.GetUserAgent()));
                    }

                    return true;
                }
                catch (Exception ex)
                {
                    Options.SPOptions.Logger.WriteError("Error in Saml2 for " + Request.Path, ex);
                    throw;
                }
            }

            return false;
        }

        private async Task AugmentAuthenticationGrantWithLogoutClaims(IOwinContext context)
        {
            var grant = context.Authentication.AuthenticationResponseGrant;
            var externalIdentity = await context.Authentication.AuthenticateAsync(Options.SignInAsAuthenticationType);
            var sessionIdClaim = externalIdentity?.Identity.FindFirst(Saml2ClaimTypes.SessionIndex);
            var externalLogutNameIdClaim = externalIdentity?.Identity.FindFirst(Saml2ClaimTypes.LogoutNameIdentifier);

            if (grant == null || externalIdentity == null || sessionIdClaim == null || externalLogutNameIdClaim == null)
            {
                return;
            }

            // Need to create new claims because the claim has a back pointer
            // to the identity it belongs to.
            grant.Identity.AddClaim(new Claim(
                sessionIdClaim.Type,
                sessionIdClaim.Value,
                sessionIdClaim.ValueType,
                sessionIdClaim.Issuer));

            grant.Identity.AddClaim(new Claim(
                externalLogutNameIdClaim.Type,
                externalLogutNameIdClaim.Value,
                externalLogutNameIdClaim.ValueType,
                externalLogutNameIdClaim.Issuer));
        }
    }
}
