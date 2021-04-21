using FluentAssertions;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owin;
using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.Metadata;
using Sustainsys.Saml2.Saml2P;
using Sustainsys.Saml2.WebSso;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace Sustainsys.Saml2.Owin.Tests
{
    using Microsoft.Owin.Infrastructure;
    using Microsoft.Owin.Security.DataProtection;
    using NSubstitute;
    using Saml2.Exceptions;
    using Sustainsys.Saml2.TestHelpers;
    using System.Configuration;
    using System.Net.Http;
    using System.Security.Cryptography.Xml;
    using System.Web;
    using AuthenticateDelegate = Func<string[], Action<IIdentity, IDictionary<string, string>, IDictionary<string, object>, object>, object, Task>;

    [TestClass]
    public class Saml2AuthenticationMiddlewareTests
    {
        ClaimsPrincipal originalPrincipal;

        [TestInitialize]
        public void Initialize()
        {
            originalPrincipal = ClaimsPrincipal.Current;
        }

        [TestCleanup]
        public void Cleanup()
        {
            Thread.CurrentPrincipal = originalPrincipal;
        }

        [TestMethod]
        public void Saml2AuthenticationMiddleware_CtorNullChecksOptions()
        {
            Action a = () => new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(0, null), CreateAppBuilder(),
                null);

            a.Should().Throw<ArgumentNullException>("options");
        }

        [TestMethod]
        public void Saml2AuthenticationMiddleware_CtorNullChecksApp()
        {
            Action a = () => new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(0, null), null, new Saml2AuthenticationOptions(true));

            a.Should().Throw<ArgumentNullException>("app");
        }

        const string DefaultSignInAsAuthenticationType = "MyDefaultSignInAsAuthTypeForTesting";

        private static IAppBuilder CreateAppBuilder()
        {
            var app = Substitute.For<IAppBuilder>();
            app.Properties.Returns(new Dictionary<string, object>()
            {
                { "host.AppName", "ABCD1234" }
            });
            app.SetDefaultSignInAsAuthenticationType(DefaultSignInAsAuthenticationType);
            return app;
        }

        [TestMethod]
        public void Saml2AuthenticationMiddleware_CtorSetsDefaultAuthOption()
        {
            var options = new Saml2AuthenticationOptions(true);

            options.SignInAsAuthenticationType.Should().BeNull();

            new Saml2AuthenticationMiddleware(new StubOwinMiddleware(0, null),
                CreateAppBuilder(), options);

            options.SignInAsAuthenticationType.Should().Be(DefaultSignInAsAuthenticationType);
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_RedirectsOnSpecificAuthChallenge_WhenPassive()
        {
            var middleware = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(401, new AuthenticationResponseChallenge(
                    new string[] { "Saml2" }, null)), CreateAppBuilder(),
                new Saml2AuthenticationOptions(true)
                { AuthenticationMode = AuthenticationMode.Passive });

            var context = OwinTestHelpers.CreateOwinContext();

            await middleware.Invoke(context);

            context.Response.StatusCode.Should().Be(303);
            context.Response.Headers["Location"].Should().StartWith("https://idp.example.com/idp");
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_DoesntRedirectOnUnSpecificAuthChallenge_WhenPassive()
        {
            var middleware = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(401, new AuthenticationResponseChallenge(
                    new string[0], null)), CreateAppBuilder(),
                new Saml2AuthenticationOptions(true)
                { AuthenticationMode = AuthenticationMode.Passive });

            var context = OwinTestHelpers.CreateOwinContext();

            await middleware.Invoke(context);

            context.Response.StatusCode.Should().Be(401);
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_RedirectsOnAuthChallenge_WhenActive()
        {
            var middleware = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(401, new AuthenticationResponseChallenge(
                    new string[0], null)), CreateAppBuilder(),
                new Saml2AuthenticationOptions(true)
                { AuthenticationMode = AuthenticationMode.Active });

            var context = OwinTestHelpers.CreateOwinContext();

            await middleware.Invoke(context);

            context.Response.StatusCode.Should().Be(303);
            context.Response.Headers["Location"].Should().StartWith("https://idp.example.com/idp");
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_RedirectToIdp_HonorsCommandResultHandled()
        {
            var options = new Saml2AuthenticationOptions(true)
            {
                AuthenticationMode = AuthenticationMode.Active,
                Notifications = new Saml2Notifications
                {
                    SignInCommandResultCreated = (cr, r) =>
                    {
                        cr.HandledResult = true;
                    }
                }
            };

            var middleware = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(401, new AuthenticationResponseChallenge(
                    new string[0], null)), CreateAppBuilder(),
                options);

            var context = OwinTestHelpers.CreateOwinContext();

            await middleware.Invoke(context);

            context.Response.StatusCode.Should().Be(401);
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_CreatesPostOnAuthChallenge()
        {
            var middleware = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(401, new AuthenticationResponseChallenge(
                    new string[] { "Saml2" }, new AuthenticationProperties(
                        new Dictionary<string, string>()
                        {
                            { "idp", "https://idp4.example.com" }
                        }))),
                CreateAppBuilder(),
                new Saml2AuthenticationOptions(true));

            var context = OwinTestHelpers.CreateOwinContext();

            await middleware.Invoke(context);

            context.Response.StatusCode.Should().Be(200);
            context.Response.Body.Seek(0, SeekOrigin.Begin);

            // Fix to #295, where content length is incorrectly set to 0 by the
            // next middleware. It appears as it works if the content length is
            // simply removed. See discussion in GitHub issue #295.
            context.Response.ContentLength.Should().NotHaveValue();

            using (var reader = new StreamReader(context.Response.Body))
            {
                string bodyContent = reader.ReadToEnd();

                // Checking some random stuff in body to make sure it looks like a SAML Post.
                bodyContent.Should().Contain("<form action");
                bodyContent.Should().Contain("<input type=\"hidden\" name=\"SAMLRequest\"");
            }
        }


        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_CreatesSignedPostOnAuthChallenge()
        {
            var middleware = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(401, new AuthenticationResponseChallenge(
                    new string[] { "Saml2" }, new AuthenticationProperties(
                        new Dictionary<string, string>()
                        {
                            { "idp", "https://idp4.example.com" }
                        }))),
                CreateAppBuilder(),
                new Saml2AuthenticationOptions(true)
                );

            var context = OwinTestHelpers.CreateOwinContext();

            await middleware.Invoke(context);

            context.Response.StatusCode.Should().Be(200);
            context.Response.Body.Seek(0, SeekOrigin.Begin);

            // Fix to #295, where content length is incorrectly set to 0 by the
            // next middleware. It appears as it works if the content length is
            // simply removed. See discussion in GitHub issue #295.
            context.Response.ContentLength.Should().NotHaveValue();

            using (var reader = new StreamReader(context.Response.Body))
            {
                string bodyContent = reader.ReadToEnd();

                // Checking some random stuff in body to make sure it looks like a SAML Post.
                bodyContent.Should().Contain("<form action");
                bodyContent.Should().Contain("<input type=\"hidden\" name=\"SAMLRequest\"");
            }
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_CreatesRedirectOnAuthRevoke()
        {
            var revoke = new AuthenticationResponseRevoke(new string[0]);

            var options = new Saml2AuthenticationOptions(true);
            options.SPOptions.PublicOrigin = new Uri("https://sp.example.com/ExternalPath/");
            options.SPOptions.Compatibility.StrictOwinAuthenticationMode = false;

            var subject = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(200, revoke: revoke),
                CreateAppBuilder(),
                options);

            var context = OwinTestHelpers.CreateOwinContext();
            context.Request.Scheme = "http";
            context.Request.Host = new HostString("sp-internal.example.com");
            context.Request.PathBase = new PathString("/InternalPath");
            context.Request.Path = new PathString("/LoggedOut");
            context.Request.User = new ClaimsPrincipal(
                new ClaimsIdentity(new Claim[]
                {
                    new Claim(Saml2ClaimTypes.LogoutNameIdentifier, ",,,,NameId", null, "https://idp.example.com"),
                    new Claim(Saml2ClaimTypes.SessionIndex, "SessionId", null, "https://idp.example.com")
                }, "Federation"));

            await subject.Invoke(context);

            context.Response.StatusCode.Should().Be(303);
            context.Response.Headers["Location"].Should().StartWith("https://idp.example.com/logout?SAMLRequest");
            var returnUrl = ExtractRequestState(options.DataProtector, context).ReturnUrl;

            returnUrl.Should().Be("/ExternalPath/LoggedOut");
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_AuthRevoke_HonorsCommandResultHandled()
        {
            var revoke = new AuthenticationResponseRevoke(new string[0]);

            var options = new Saml2AuthenticationOptions(true)
            {
                Notifications = new Saml2Notifications
                {
                    LogoutCommandResultCreated = cr =>
                    {
                        cr.HandledResult = true;
                    }
                }
            };

            var subject = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(200, revoke: revoke),
                CreateAppBuilder(),
                options);

            var context = OwinTestHelpers.CreateOwinContext();
            context.Request.Scheme = "http";
            context.Request.Host = new HostString("sp-internal.example.com");
            context.Request.PathBase = new PathString("/InternalPath");
            context.Request.Path = new PathString("/LoggedOut");
            context.Request.User = new ClaimsPrincipal(
                new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, "NameId", null, "https://idp.example.com"),
                    new Claim(Saml2ClaimTypes.SessionIndex, "SessionId", null, "https://idp.example.com")
                }, "Federation"));

            await subject.Invoke(context);

            context.Response.StatusCode.Should().Be(200);
        }

        private static StoredRequestState ExtractRequestState(IDataProtector dataProtector, OwinContext context)
        {
            var cookieData = context.Response.Headers["Set-Cookie"].Split(';', '=')[1];

            return new StoredRequestState(
                dataProtector.Unprotect(
                    HttpRequestData.GetBinaryData(cookieData)));
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_CreatesRedirectOnAuthRevoke_UsesAuthPropsReturnUrl()
        {
            var authPropsReturnUrl = "http://sp.exmample.com/AuthPropsLogout";

            var revoke = new AuthenticationResponseRevoke(
                new string[0],
                new AuthenticationProperties { RedirectUri = authPropsReturnUrl });

            var options = new Saml2AuthenticationOptions(true);
            options.SPOptions.PublicOrigin = new Uri("https://sp.example.com/ExternalPath/");

            var subject = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(303, revoke: revoke),
                CreateAppBuilder(),
                options);

            var context = OwinTestHelpers.CreateOwinContext();
            context.Response.Headers["Location"] = "http://sp.example.com/locationHeader";
            context.Request.User = new ClaimsPrincipal(
                new ClaimsIdentity(new Claim[]
                {
                    new Claim(Saml2ClaimTypes.LogoutNameIdentifier, ",,,,NameId", null, "https://idp.example.com"),
                    new Claim(Saml2ClaimTypes.SessionIndex, "SessionId", null, "https://idp.example.com")
                }, "Federation"));

            await subject.Invoke(context);

            var cookieValue = context.Response.Headers["Set-Cookie"].Split(';', '=')[1];

            var returnUrl = new StoredRequestState(options.DataProtector.Unprotect(
                HttpRequestData.GetBinaryData(cookieValue))).ReturnUrl;

            returnUrl.Should().Be(authPropsReturnUrl);
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_DoesntRedirectOnUnspecifiedAuthRevoke_WhenPassiveAndStrictCompatibility()
        {
            var options = new Saml2AuthenticationOptions(true)
            {
                AuthenticationMode = AuthenticationMode.Passive,
            };
            options.SPOptions.Compatibility.StrictOwinAuthenticationMode = true;

            var subject = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(200, revoke: new AuthenticationResponseRevoke(new string[0])),
                CreateAppBuilder(),
                options);

            var context = OwinTestHelpers.CreateOwinContext();

            Thread.CurrentPrincipal = new ClaimsPrincipal(
                new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, "NameId", null, "https://idp.example.com"),
                    new Claim(Saml2ClaimTypes.SessionIndex, "SessionId", null, "https://idp.example.com")
                }, "Federation"));

            await subject.Invoke(context);

            context.Response.StatusCode.Should().Be(200);
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_CreatesRedirectOnSpecifiedAuthRevoke_WhenPassive()
        {
            var subject = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(200, revoke: new AuthenticationResponseRevoke(
                    new string[] { "Saml2" })),
                CreateAppBuilder(),
                new Saml2AuthenticationOptions(true)
                {
                    AuthenticationMode = AuthenticationMode.Passive
                });

            var context = OwinTestHelpers.CreateOwinContext();

            context.Request.User = new ClaimsPrincipal(
                new ClaimsIdentity(new Claim[]
                {
                    new Claim(Saml2ClaimTypes.LogoutNameIdentifier, ",,,,NameId", null, "https://idp.example.com"),
                    new Claim(Saml2ClaimTypes.SessionIndex, "SessionId", null, "https://idp.example.com")
                }, "Federation"));

            await subject.Invoke(context);

            context.Response.StatusCode.Should().Be(303);
            context.Response.Headers["Location"].Should().StartWith("https://idp.example.com/logout?SAMLRequest");
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_OnlyExecutesLogoutCommandOnce()
        {
            // A test case for a bug. If logout command is called through the /Saml2/Logout endpoint,
            // it will cause a logout of the local session. Which caused the automatic processing
            // of logout to run the logout command again.

            Saml2AuthenticationOptions options = new Saml2AuthenticationOptions(true)
            {
                AuthenticationMode = AuthenticationMode.Passive
            };

            var subject = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(200, revoke: new AuthenticationResponseRevoke(
                    new string[0])),
                CreateAppBuilder(),
                options);

            var context = OwinTestHelpers.CreateOwinContext();

            context.Request.Path = new PathString("/Saml2/Logout");
            context.Request.User = new ClaimsPrincipal(
                new ClaimsIdentity(new Claim[]
                {
                    new Claim(Saml2ClaimTypes.LogoutNameIdentifier, ",,,,NameId", null, "https://idp.example.com"),
                    new Claim(Saml2ClaimTypes.SessionIndex, "SessionId", null, "https://idp.example.com")
                }, "Federation"));

            var logoutCommandCalled = false;
            options.Notifications.LogoutCommandResultCreated = cr =>
            {
                logoutCommandCalled.Should().BeFalse();
                logoutCommandCalled = true;
            };

            await subject.Invoke(context);
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_HandlesLogoutResponse()
        {
            var app = CreateAppBuilder();
            var options = new Saml2AuthenticationOptions(true);
            var subject = new Saml2AuthenticationMiddleware(
                null,
                app,
                options);

            var context = OwinTestHelpers.CreateOwinContext();

            var relayState = "MyRelayState";
            var response = new Saml2LogoutResponse(Saml2StatusCode.Success)
            {
                DestinationUrl = new Uri("https://sp.example.com/Saml2/Logout"),
                RelayState = relayState,
                SigningCertificate = SignedXmlHelper.TestCert,
                SigningAlgorithm = SignedXml.XmlDsigRSASHA256Url,
                Issuer = new EntityId("https://idp.example.com")
            };
            var requestUri = Saml2Binding.Get(Saml2BindingType.HttpRedirect).Bind(response).Location;

            var cookieData = HttpRequestData.ConvertBinaryData(
                    options.DataProtector.Protect(
                        new StoredRequestState(null, new Uri("http://loggedout.example.com/"), null, null)
                            .Serialize()));
            context.Request.Headers["Cookie"] = $"{StoredRequestState.CookieNameBase}{relayState}={cookieData}";
            context.Request.Path = new PathString(requestUri.AbsolutePath);
            context.Request.QueryString = new QueryString(requestUri.Query.TrimStart('?'));

            Thread.CurrentPrincipal = new ClaimsPrincipal(
                new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, "NameId", null, "https://idp.example.com"),
                    new Claim(Saml2ClaimTypes.SessionIndex, "SessionId", null, "https://idp.example.com")
                }, "Federation"));

            await subject.Invoke(context);

            context.Response.StatusCode.Should().Be(303);
            context.Response.Headers["Location"].Should().Be("http://loggedout.example.com/");
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_LogoutsOnLogoutRequest()
        {
            var options = new Saml2AuthenticationOptions(true);
            var subject = new Saml2AuthenticationMiddleware(null, CreateAppBuilder(), options);

            var context = OwinTestHelpers.CreateOwinContext();

            var request = new Saml2LogoutRequest()
            {
                SessionIndex = "SessionId",
                DestinationUrl = new Uri("http://sp.example.com/Saml2/Logout"),
                NameId = new Saml2NameIdentifier("NameId"),
                Issuer = new EntityId("https://idp.example.com"),
                SigningCertificate = SignedXmlHelper.TestCert,
                SigningAlgorithm = SignedXml.XmlDsigRSASHA256Url
            };

            var url = Saml2Binding.Get(Saml2BindingType.HttpRedirect)
                .Bind(request).Location;

            context.Request.Path = new PathString(url.AbsolutePath);
            context.Request.QueryString = new QueryString(url.Query.TrimStart('?'));

            await subject.Invoke(context);

            context.Response.StatusCode.Should().Be(303);
            context.Response.Headers["Location"].Should().StartWith("https://idp.example.com/logout?SAMLResponse");

            context.Authentication.AuthenticationResponseRevoke.Should().NotBeNull();
            context.Authentication.AuthenticationResponseRevoke.AuthenticationTypes
                .Should().BeEmpty();
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_LogoutRequest_HonorsCommandResultHandled()
        {
            var options = new Saml2AuthenticationOptions(true)
            {
                Notifications = new Saml2Notifications
                {
                    LogoutCommandResultCreated = cr =>
                    {
                        cr.HandledResult = true;
                    }
                }
            };

            var subject = new Saml2AuthenticationMiddleware(null, CreateAppBuilder(), options);

            var context = OwinTestHelpers.CreateOwinContext();

            var request = new Saml2LogoutRequest()
            {
                SessionIndex = "SessionId",
                DestinationUrl = new Uri("http://sp.example.com/Saml2/Logout"),
                NameId = new Saml2NameIdentifier("NameId"),
                Issuer = new EntityId("https://idp.example.com"),
                SigningCertificate = SignedXmlHelper.TestCert,
                SigningAlgorithm = SignedXml.XmlDsigRSASHA256Url
            };

            var url = Saml2Binding.Get(Saml2BindingType.HttpRedirect)
                .Bind(request).Location;

            context.Request.Path = new PathString(url.AbsolutePath);
            context.Request.QueryString = new QueryString(url.Query.TrimStart('?'));

            await subject.Invoke(context);

            context.Response.StatusCode.Should().Be(200);
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_NoRedirectOnNon401()
        {
            var middleware = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(200, new AuthenticationResponseChallenge(
                    new string[] { "SustainsysSaml2" }, null)),
                CreateAppBuilder(),
                new Saml2AuthenticationOptions(true));

            var context = OwinTestHelpers.CreateOwinContext();

            await middleware.Invoke(context);

            context.Response.StatusCode.Should().Be(200);
            context.Response.Headers["Location"].Should().BeNull();
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_NoRedirectWithChallengeOfDifferentType()
        {
            var middleware = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(401, new AuthenticationResponseChallenge(
                        new string[] { "SomeThingElse" }, null)),
                    CreateAppBuilder(),
                    new Saml2AuthenticationOptions(true));

            var context = OwinTestHelpers.CreateOwinContext();

            await middleware.Invoke(context);

            context.Response.StatusCode.Should().Be(401);
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_RedirectToSecondIdp_AuthenticationProperties()
        {
            var secondIdp = Options.FromConfiguration.IdentityProviders[1];
            var secondDestination = secondIdp.SingleSignOnServiceUrl;
            var secondEntityId = secondIdp.EntityId;

            var middleware = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(401, new AuthenticationResponseChallenge(
                    new string[] { "Saml2" }, new AuthenticationProperties(
                        new Dictionary<string, string>()
                        {
                            { "idp", secondEntityId.Id }
                        }))),
                        CreateAppBuilder(), new Saml2AuthenticationOptions(true));

            var context = OwinTestHelpers.CreateOwinContext();
            await middleware.Invoke(context);

            context.Response.StatusCode.Should().Be(303);
            context.Response.Headers["Location"].Should().StartWith(secondDestination.ToString());
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_RedirectToSecondIdp_OwinEnvironment()
        {
            var secondIdp = Options.FromConfiguration.IdentityProviders[1];
            var secondDestination = secondIdp.SingleSignOnServiceUrl;
            var secondEntityId = secondIdp.EntityId;

            var middleware = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(401, new AuthenticationResponseChallenge(
                    new string[] { "Saml2" }, new AuthenticationProperties())),
                        CreateAppBuilder(), new Saml2AuthenticationOptions(true));

            var context = OwinTestHelpers.CreateOwinContext();
            context.Environment["saml2.idp"] = secondEntityId;
            await middleware.Invoke(context);

            context.Response.StatusCode.Should().Be(303);
            context.Response.Headers["Location"].Should().StartWith(secondDestination.ToString());
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_RedirectOnChallengeForAuthTypeInOptions()
        {
            var authenticationType = "someAuthName";

            var middleware = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(401, new AuthenticationResponseChallenge(
                    new string[] { authenticationType }, null)),
                CreateAppBuilder(),
                new Saml2AuthenticationOptions(true)
                {
                    AuthenticationType = authenticationType
                });

            var context = OwinTestHelpers.CreateOwinContext();

            await middleware.Invoke(context);

            context.Response.StatusCode.Should().Be(303);
            context.Response.Headers["Location"].Should().StartWith("https://idp.example.com/idp");
        }

        private string ExtractRelayState(OwinContext context)
        {
            return HttpUtility.ParseQueryString(
                new Uri(context.Response.Headers["Location"])
                .Query)["RelayState"];
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_RedirectRemembersReturnPath()
        {
            var returnUrl = "http://sp.example.com/returnurl";

            var options = new Saml2AuthenticationOptions(true);
            var subject = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(401, new AuthenticationResponseChallenge(
                    new string[] { "Saml2" }, new AuthenticationProperties()
                    {
                        RedirectUri = returnUrl
                    })),
                    CreateAppBuilder(), options);

            var context = OwinTestHelpers.CreateOwinContext();

            await subject.Invoke(context);

            var storedState = ExtractRequestState(options.DataProtector, context);

            storedState.ReturnUrl.Should().Be(returnUrl);
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_UseConfiguredCookieManager()
        {
            var returnUrl = "http://sp.example.com/returnurl";

            var options = new Saml2AuthenticationOptions(true);
            var mockCookieManager = Substitute.For<ICookieManager>();
            options.CookieManager = mockCookieManager;

            var subject = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(401, new AuthenticationResponseChallenge(
                    new string[] { "Saml2" }, new AuthenticationProperties()
                    {
                        RedirectUri = returnUrl
                    })),
                    CreateAppBuilder(), options);

            var context = OwinTestHelpers.CreateOwinContext();

            await subject.Invoke(context);

            mockCookieManager.Received().AppendResponseCookie(
                context,
                Arg.Is<string>(value => value.StartsWith("Saml2.")),
                Arg.Is<string>(value => true),
                Arg.Is<CookieOptions>(c => c.HttpOnly && c.Path == "/"));
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_StoresAuthenticationProperties()
        {
            var returnUrl = "http://sp.example.com/returnurl";

            var prop = new AuthenticationProperties()
            {
                RedirectUri = returnUrl
            };
            prop.Dictionary["test"] = "SomeValue";

            var options = new Saml2AuthenticationOptions(true);
            var middleware = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(401,
                    new AuthenticationResponseChallenge(
                        new string[] { "Saml2" }, prop)),
                CreateAppBuilder(),
                options);

            var context = OwinTestHelpers.CreateOwinContext();

            await middleware.Invoke(context);

            var storedAuthnData = ExtractRequestState(options.DataProtector, context);

            new AuthenticationProperties(storedAuthnData.RelayData).Dictionary["test"].Should().Be("SomeValue");
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_StoresCurrentUrlIfNoneInAuthProps()
        {
            var options = new Saml2AuthenticationOptions(true);
            var middleware = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(401,
                    new AuthenticationResponseChallenge(
                        new string[] { "Saml2" }, new AuthenticationProperties())),
                CreateAppBuilder(),
                options);

            var context = OwinTestHelpers.CreateOwinContext();
            context.Request.Host = new HostString("host3");
            context.Request.Path = new PathString("/path3");
            context.Request.QueryString = new QueryString("p1=value1");

            await middleware.Invoke(context);
            var storedAuthnData = ExtractRequestState(options.DataProtector, context);
            storedAuthnData.ReturnUrl.Should().Be("http://host3/path3?p1=value1");
        }

        [TestMethod]
        [DataRow("/Saml2/Acs")]
        [DataRow("/SAML2/ACS")]
        [DataRow("/saml2/acs")]
        [DataRow("/SaMl2/AcS")]
        public async Task Saml2AuthenticationMiddleware_AcsUsesCommandResultLocation(string acsPath)
        {
            // For Owin middleware, the redirect uri is part of the
            // authentication properties, but we don't want to use it as it
            // is because it can be empty (e.g. on unsolicited responses
            // or until #182 is fixed). The redirect uri should be taken
            // from the commandresult location instead.

            var context = OwinTestHelpers.CreateOwinContext();
            context.Request.Method = "POST";

            var response =
                @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
                xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                ID = """ + MethodBase.GetCurrentMethod().Name + @""" Version=""2.0""
                IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>
                    https://idp.example.com
                </saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion
                Version=""2.0"" ID=""" + MethodBase.GetCurrentMethod().Name + @"_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";

            var bodyData = new KeyValuePair<string, string>[] {
                new KeyValuePair<string, string>("SAMLResponse",
                    Convert.ToBase64String(Encoding.UTF8.GetBytes(SignedXmlHelper.SignXml(response))))
            };

            var encodedBodyData = new FormUrlEncodedContent(bodyData);

            context.Request.Body = encodedBodyData.ReadAsStreamAsync().Result;
            context.Request.ContentType = encodedBodyData.Headers.ContentType.ToString();
            context.Request.Host = new HostString("localhost");
            context.Request.Path = new PathString(acsPath);

            var middleware = new Saml2AuthenticationMiddleware(null, CreateAppBuilder(),
                new Saml2AuthenticationOptions(true)
                {
                    SignInAsAuthenticationType = "AuthType"
                });

            await middleware.Invoke(context);

            context.Response.StatusCode.Should().Be(303);
            context.Response.Headers["Location"].Should().Be("http://localhost/LoggedIn");
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_AcsRedirectsToDefaultWithoutSignInOnUnsolicitedError()
        {
            var context = OwinTestHelpers.CreateOwinContext();
            context.Request.Method = "POST";

            var response =
                @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
                xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                ID = """ + MethodBase.GetCurrentMethod().Name + @""" Version=""2.0""
                IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>
                    https://idp.example.com
                </saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion
                Version=""2.0"" ID=""" + MethodBase.GetCurrentMethod().Name + @"_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";

            // No signature, that's an error.
            var bodyData = new KeyValuePair<string, string>[] {
                new KeyValuePair<string, string>("SAMLResponse",
                    Convert.ToBase64String(Encoding.UTF8.GetBytes(response)))
            };

            var encodedBodyData = new FormUrlEncodedContent(bodyData);

            context.Request.Body = encodedBodyData.ReadAsStreamAsync().Result;
            context.Request.ContentType = encodedBodyData.Headers.ContentType.ToString();
            context.Request.Host = new HostString("localhost");
            context.Request.Path = new PathString("/Saml2/Acs");

            var middleware = new Saml2AuthenticationMiddleware(null, CreateAppBuilder(),
                new Saml2AuthenticationOptions(true)
                {
                    SignInAsAuthenticationType = "AuthType"
                });

            await middleware.Invoke(context);

            context.Response.StatusCode.Should().Be(302);
            context.Response.Headers["Location"].Should().Be("http://localhost/LoggedIn?error=access_denied");
            context.Authentication.AuthenticationResponseGrant.Should().BeNull();
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_AcsLogsAndRedirectsToApplicationRootOnNoReturnUrlAndNoStoredRequestState()
        {
            var context = OwinTestHelpers.CreateOwinContext();
            context.Request.Method = "POST";

            var response =
                @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
                xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                ID = """ + MethodBase.GetCurrentMethod().Name + @""" Version=""2.0""
                IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>
                    https://idp.example.com
                </saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion
                Version=""2.0"" ID=""" + MethodBase.GetCurrentMethod().Name + @"_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";

            var bodyData = new KeyValuePair<string, string>[] {
                new KeyValuePair<string, string>("SAMLResponse",
                    Convert.ToBase64String(Encoding.UTF8.GetBytes(response)))
            };

            var encodedBodyData = new FormUrlEncodedContent(bodyData);

            context.Request.Body = encodedBodyData.ReadAsStreamAsync().Result;
            context.Request.ContentType = encodedBodyData.Headers.ContentType.ToString();
            context.Request.Host = new HostString("localhost");
            context.Request.Path = new PathString("/Saml2/Acs");
            context.Request.PathBase = new PathString("/ApplicationPath");

            var options = new Saml2AuthenticationOptions(true)
            {
                SignInAsAuthenticationType = "AuthType"
            };
            options.SPOptions.ReturnUrl = null;

            options.SPOptions.Logger = Substitute.For<ILoggerAdapter>();

            var subject = new Saml2AuthenticationMiddleware(
                null,
                CreateAppBuilder(),
                options);

            await subject.Invoke(context);

            context.Response.StatusCode.Should().Be(302);
            context.Response.Headers["Location"].Should().Be("http://localhost/ApplicationPath?error=access_denied");
            context.Authentication.AuthenticationResponseGrant.Should().BeNull();
            options.SPOptions.Logger.Received().WriteError(Arg.Any<string>(), null);
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_AcsRedirectsToAuthPropsReturnUriWithoutSignInOnError()
        {
            var context = OwinTestHelpers.CreateOwinContext();
            context.Request.Method = "POST";

            var authProps = new AuthenticationProperties();

            var state = new StoredRequestState(new EntityId("https://idp.example.com"),
                new Uri("http://localhost/PathInRequestState?value=42"),
                new Saml2Id("InResponseToId"),
                authProps.Dictionary);

            var relayState = SecureKeyGenerator.CreateRelayState();

            var cookieData = HttpRequestData.ConvertBinaryData(
                CreateAppBuilder().CreateDataProtector(
                    typeof(Saml2AuthenticationMiddleware).FullName)
                    .Protect(state.Serialize()));

            context.Request.Headers["Cookie"] = $"{StoredRequestState.CookieNameBase}{relayState}={cookieData}";

            var response =
                @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
                xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                ID = """ + MethodBase.GetCurrentMethod().Name + @""" Version=""2.0""
                IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>
                    https://idp.example.com
                </saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion
                Version=""2.0"" ID=""" + MethodBase.GetCurrentMethod().Name + @"_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";

            // No signature, that's an error.
            var bodyData = new KeyValuePair<string, string>[] {
                new KeyValuePair<string, string>("SAMLResponse",
                    Convert.ToBase64String(Encoding.UTF8.GetBytes(response))),
                new KeyValuePair<string, string>("RelayState",relayState)
            };

            var encodedBodyData = new FormUrlEncodedContent(bodyData);

            context.Request.Body = encodedBodyData.ReadAsStreamAsync().Result;
            context.Request.ContentType = encodedBodyData.Headers.ContentType.ToString();
            context.Request.Host = new HostString("localhost");
            context.Request.Path = new PathString("/Saml2/Acs");

            var middleware = new Saml2AuthenticationMiddleware(null, CreateAppBuilder(),
                new Saml2AuthenticationOptions(true)
                {
                    SignInAsAuthenticationType = "AuthType"
                });

            await middleware.Invoke(context);

            context.Response.StatusCode.Should().Be(302);
            context.Response.Headers["Location"].Should().Be("http://localhost/PathInRequestState?value=42&error=access_denied");
            context.Authentication.AuthenticationResponseGrant.Should().BeNull();
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_AcsRedirectsToAuthProps_StoredRequestStateWithNoReturnUrl()
        {
            var context = OwinTestHelpers.CreateOwinContext();
            context.Request.Method = "POST";

            var authProps = new AuthenticationProperties();

            var state = new StoredRequestState(new EntityId("https://idp.example.com"),
                null,
                new Saml2Id("InResponseToId"),
                authProps.Dictionary);

            var relayState = SecureKeyGenerator.CreateRelayState();

            var cookieData = HttpRequestData.ConvertBinaryData(
                CreateAppBuilder().CreateDataProtector(
                    typeof(Saml2AuthenticationMiddleware).FullName)
                    .Protect(state.Serialize()));

            context.Request.Headers["Cookie"] = $"{StoredRequestState.CookieNameBase}{relayState}={cookieData}";

            var response =
                @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
                xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                ID = """ + MethodBase.GetCurrentMethod().Name + @""" Version=""2.0""
                IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>
                    https://idp.example.com
                </saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion
                Version=""2.0"" ID=""" + MethodBase.GetCurrentMethod().Name + @"_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";

            // No signature, that's an error.
            var bodyData = new KeyValuePair<string, string>[] {
                new KeyValuePair<string, string>("SAMLResponse",
                    Convert.ToBase64String(Encoding.UTF8.GetBytes(response))),
                new KeyValuePair<string, string>("RelayState",relayState)
            };

            var encodedBodyData = new FormUrlEncodedContent(bodyData);

            context.Request.Body = encodedBodyData.ReadAsStreamAsync().Result;
            context.Request.ContentType = encodedBodyData.Headers.ContentType.ToString();
            context.Request.Host = new HostString("localhost");
            context.Request.Path = new PathString("/Saml2/Acs");

            var middleware = new Saml2AuthenticationMiddleware(null, CreateAppBuilder(),
                new Saml2AuthenticationOptions(true)
                {
                    SignInAsAuthenticationType = "AuthType"
                });

            await middleware.Invoke(context);

            context.Response.StatusCode.Should().Be(302);
            context.Response.Headers["Location"].Should().Be("http://localhost/LoggedIn?error=access_denied");
            context.Authentication.AuthenticationResponseGrant.Should().BeNull();
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_AcsWorks()
        {
            var context = OwinTestHelpers.CreateOwinContext();
            context.Request.Method = "POST";

            var authProps = new AuthenticationProperties()
            {
                IssuedUtc = new DateTime(1975, 05, 05, 05, 05, 05, DateTimeKind.Utc)
            };
            authProps.Dictionary["Test"] = "TestValue";

            var state = new StoredRequestState(new EntityId("https://idp.example.com"),
                new Uri("http://localhost/LoggedIn"),
                new Saml2Id("InResponseToId"),
                authProps.Dictionary);

            var relayState = SecureKeyGenerator.CreateRelayState();

            var cookieData = HttpRequestData.ConvertBinaryData(
                CreateAppBuilder().CreateDataProtector(
                    typeof(Saml2AuthenticationMiddleware).FullName)
                    .Protect(state.Serialize()));

            context.Request.Headers["Cookie"] = $"{StoredRequestState.CookieNameBase}{relayState}={cookieData}";

            var response =
            @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
                xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                ID = """ + MethodBase.GetCurrentMethod().Name + @""" Version=""2.0""
                IssueInstant=""2013-01-01T00:00:00Z"" InResponseTo=""InResponseToId"" >
                <saml2:Issuer>
                    https://idp.example.com
                </saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion
                Version=""2.0"" ID=""" + MethodBase.GetCurrentMethod().Name + @"_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";

            var bodyData = new KeyValuePair<string, string>[] {
                new KeyValuePair<string, string>("SAMLResponse",
                    Convert.ToBase64String(Encoding.UTF8.GetBytes(SignedXmlHelper.SignXml(response)))),
                new KeyValuePair<string, string>("RelayState",relayState)
            };

            var encodedBodyData = new FormUrlEncodedContent(bodyData);

            context.Request.Body = encodedBodyData.ReadAsStreamAsync().Result;
            context.Request.ContentType = encodedBodyData.Headers.ContentType.ToString();
            context.Request.Host = new HostString("localhost");
            context.Request.Path = new PathString("/Saml2/Acs");

            var signInAsAuthenticationType = "AuthType";
            var ids = new ClaimsIdentity[] { new ClaimsIdentity(signInAsAuthenticationType) };
            ids[0].AddClaim(new Claim(ClaimTypes.NameIdentifier, "SomeUser", null, "https://idp.example.com"));

            var subject = new Saml2AuthenticationMiddleware(null, CreateAppBuilder(),
                OwinStubFactory.CreateOwinOptions());

            await subject.Invoke(context);

            context.Response.StatusCode.Should().Be(303);
            context.Response.Headers["Location"].Should().Be("http://localhost/LoggedIn");
            context.Response.Headers["Set-Cookie"].Should().Be($"{StoredRequestState.CookieNameBase}{relayState}=; path=/; expires=Thu, 01-Jan-1970 00:00:00 GMT");

            context.Authentication.AuthenticationResponseGrant.Principal.Identities
                .Should().BeEquivalentTo(ids, opt => opt.IgnoringCyclicReferences());

            context.Authentication.AuthenticationResponseGrant.Properties.RedirectUri
                .Should().Be("http://localhost/LoggedIn",
                "the StoredRequestState.ReturnUrl should overtake the value in the AuthProperties and be stored in the AuthProps");

            context.Authentication.AuthenticationResponseGrant.Properties.Dictionary["Test"]
                .Should().Be("TestValue");

            context.Authentication.AuthenticationResponseGrant.Properties.IssuedUtc
                .Should().Be(authProps.IssuedUtc);

            context.Authentication.AuthenticationResponseGrant.Properties.AllowRefresh.Should().NotHaveValue("AllowRefresh should not be specified if no SessionOnOrAfter is specified");
            context.Authentication.AuthenticationResponseGrant.Properties.ExpiresUtc.Should().NotHaveValue("ExpiresUtc should not be set if no SessionNotOnOrAfter is specified");
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_Acs_HonorsCommandResultHandled()
        {
            var context = OwinTestHelpers.CreateOwinContext();
            context.Request.Method = "POST";

            var response =
            @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
                xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                ID = """ + MethodBase.GetCurrentMethod().Name + @""" Version=""2.0""
                IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>
                    https://idp.example.com
                </saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion
                Version=""2.0"" ID=""" + MethodBase.GetCurrentMethod().Name + @"_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";

            var bodyData = new KeyValuePair<string, string>[] {
                new KeyValuePair<string, string>("SAMLResponse",
                    Convert.ToBase64String(Encoding.UTF8.GetBytes(SignedXmlHelper.SignXml(response)))),
            };

            var encodedBodyData = new FormUrlEncodedContent(bodyData);

            context.Request.Body = encodedBodyData.ReadAsStreamAsync().Result;
            context.Request.ContentType = encodedBodyData.Headers.ContentType.ToString();
            context.Request.Host = new HostString("localhost");
            context.Request.Path = new PathString("/Saml2/Acs");

            var options = OwinStubFactory.CreateOwinOptions();
            options.Notifications.AcsCommandResultCreated = (cr, r) =>
            {
                cr.HandledResult = true;
            };

            var subject = new Saml2AuthenticationMiddleware(
                null, CreateAppBuilder(), options);

            await subject.Invoke(context);

            context.Response.StatusCode.Should().Be(200);
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_Acs_HonorsSessionNotOnOrAfter()
        {
            var context = OwinTestHelpers.CreateOwinContext();
            context.Request.Method = "POST";

            var response =
            @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
                xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                ID = """ + MethodBase.GetCurrentMethod().Name + @""" Version=""2.0""
                IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>
                    https://idp.example.com
                </saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion
                Version=""2.0"" ID=""" + MethodBase.GetCurrentMethod().Name + $@"_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                    <saml2:AuthnStatement AuthnInstant=""{DateTime.UtcNow.ToSaml2DateTimeString()}"" SessionNotOnOrAfter=""2050-01-01T00:00:00Z"">
                        <saml2:AuthnContext>
                            <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
                        </saml2:AuthnContext>
                    </saml2:AuthnStatement>
                </saml2:Assertion>
            </saml2p:Response>";

            var bodyData = new KeyValuePair<string, string>[] {
                new KeyValuePair<string, string>("SAMLResponse",
                    Convert.ToBase64String(Encoding.UTF8.GetBytes(SignedXmlHelper.SignXml(response)))),
            };

            var encodedBodyData = new FormUrlEncodedContent(bodyData);

            context.Request.Body = encodedBodyData.ReadAsStreamAsync().Result;
            context.Request.ContentType = encodedBodyData.Headers.ContentType.ToString();
            context.Request.Host = new HostString("localhost");
            context.Request.Path = new PathString("/Saml2/Acs");

            var options = OwinStubFactory.CreateOwinOptions();

            var subject = new Saml2AuthenticationMiddleware(
                null, CreateAppBuilder(), options);

            await subject.Invoke(context);

            context.Authentication.AuthenticationResponseGrant.Properties
                .AllowRefresh.Should().BeFalse("AllowRefresh should be false if SessionNotOnOrAfter is specified");
            context.Authentication.AuthenticationResponseGrant.Properties
                .ExpiresUtc.Should().BeCloseTo(
                new DateTimeOffset(2050, 1, 1, 0, 0, 0, new TimeSpan(0)),
                because: "SessionNotOnOrAfter should be honored.");
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_MetadataWorks()
        {
            var context = OwinTestHelpers.CreateOwinContext();
            context.Request.Host = new HostString("localhost");
            context.Request.Path = new PathString("/Saml2");

            var middleware = new Saml2AuthenticationMiddleware(
                null,
                CreateAppBuilder(),
                new Saml2AuthenticationOptions(true));

            await middleware.Invoke(context);

            context.Response.ContentType.Should().Contain("application/samlmetadata+xml");
            context.Response.Headers["Content-Disposition"].Should().Be(
                "attachment; filename=\"github.com_Sustainsys_Saml2.xml\"");

            context.Response.Body.Seek(0, SeekOrigin.Begin);
            var xmlData = XDocument.Load(context.Response.Body);

            xmlData.Document.Root.Name.Should().Be(Saml2Namespaces.Saml2Metadata + "EntityDescriptor");
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_SignInUrlRedirectsToIdp()
        {
            var context = OwinTestHelpers.CreateOwinContext();
            context.Request.Host = new HostString("localhost");
            var signinPath = "/Saml2/SignIn";
            context.Request.Path = new PathString(signinPath);
            context.Request.QueryString = new QueryString("ReturnUrl=%2FHome&idp=https%3A%2F%2Fidp2.example.com");

            var options = new Saml2AuthenticationOptions(true);
            var middleware = new Saml2AuthenticationMiddleware(
                null, CreateAppBuilder(), options);

            await middleware.Invoke(context);

            context.Response.StatusCode.Should().Be(303);
            context.Response.Headers["Location"].Should().StartWith("https://idp2.example.com/idp?SAMLRequest");

            ExtractRelayState(context);

            var storedAuthnData = ExtractRequestState(options.DataProtector, context);

            storedAuthnData.ReturnUrl.Should().Be("/Home");
        }

        [TestMethod]
        public void Saml2AuthenticationMiddleware_WorksOnNullDiscoveryResponseUrl()
        {
            var context = OwinTestHelpers.CreateOwinContext();

            var subject = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(200, null),
                CreateAppBuilder(),
                new Saml2AuthenticationOptions(false)
                {
                    SPOptions = new SPOptions()
                    {
                        EntityId = new EntityId("http://localhost/metadata")
                    }
                });

            subject.Awaiting(async s => await s.Invoke(context)).Should().NotThrow();
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_AugmentsGeneratedClaimsWithLogoutInfo()
        {
            var context = OwinTestHelpers.CreateOwinContext();

            string[] specifiedAuthTypes = null;

            string logoutInfoClaimValue = ",,urn:format,,Saml2NameId";

            // Emulate the external cookie middleware.
            context.Set<AuthenticateDelegate>("security.Authenticate",
                (authTypes, callback, state) =>
                {
                    specifiedAuthTypes = authTypes;
                    var logoutInfoClaim = new Claim(
                        Saml2ClaimTypes.LogoutNameIdentifier,
                        logoutInfoClaimValue,
                        null,
                        "http://idp.example.com");

                    callback(new ClaimsIdentity(new Claim[]
                        {
                            logoutInfoClaim,
                            new Claim(Saml2ClaimTypes.SessionIndex, "SessionId", null, "http://idp.example.com"),
                            new Claim(ClaimTypes.Role, "SomeRole", null, "http://idp.example.com")
                        }, "Federation"),
                        new Dictionary<string, string>(),
                        new Dictionary<string, object>(),
                        state);
                    return Task.FromResult(0);
                });

            var options = new Saml2AuthenticationOptions(true);

            var subject = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(303, grant: new AuthenticationResponseGrant(
                    new ClaimsIdentity(new Claim[]
                    {
                        new Claim(ClaimTypes.NameIdentifier, "ApplicationNameId")
                    }, "ApplicationIdentity"), new AuthenticationProperties())),
                CreateAppBuilder(),
                options);

            await subject.Invoke(context);

            specifiedAuthTypes.Should().HaveCount(1)
                .And.Subject.Single().Should().Be(DefaultSignInAsAuthenticationType);

            var expected = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.NameIdentifier, "ApplicationNameId"),
                new Claim(Saml2ClaimTypes.SessionIndex, "SessionId", null, "http://idp.example.com"),
                new Claim(Saml2ClaimTypes.LogoutNameIdentifier, logoutInfoClaimValue, null, "http://idp.example.com")
        }, "ApplicationIdentity");

            context.Authentication.AuthenticationResponseGrant.Identity
                .Should().BeEquivalentTo(expected, opt => opt.IgnoringCyclicReferences());
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_DoesntAugmentsGeneratedClaimsWhenSessionIndexIsMissing()
        {
            var context = OwinTestHelpers.CreateOwinContext();

            string[] specifiedAuthTypes = null;

            context.Set<AuthenticateDelegate>("security.Authenticate",
                (authTypes, callback, state) =>
                {
                    specifiedAuthTypes = authTypes;
                    callback(new ClaimsIdentity(new Claim[]
                        {
                            new Claim(ClaimTypes.NameIdentifier, "Saml2NameId", null, "http://idp.example.com"),
                            new Claim(ClaimTypes.Role, "SomeRole", null, "http://idp.example.com")
                        }, "Federation"),
                        new Dictionary<string, string>(),
                        new Dictionary<string, object>(),
                        state);
                    return Task.FromResult(0);
                });

            var options = new Saml2AuthenticationOptions(true);

            var subject = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(303, grant: new AuthenticationResponseGrant(
                    new ClaimsIdentity(new Claim[]
                    {
                        new Claim(ClaimTypes.NameIdentifier, "ApplicationNameId")
                    }, "ApplicationIdentity"), new AuthenticationProperties())),
                CreateAppBuilder(),
                options);

            await subject.Invoke(context);

            specifiedAuthTypes.Should().HaveCount(1)
                .And.Subject.Single().Should().Be(DefaultSignInAsAuthenticationType);

            var expected = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.NameIdentifier, "ApplicationNameId"),
            }, "ApplicationIdentity");

            context.Authentication.AuthenticationResponseGrant.Identity
                .Should().BeEquivalentTo(expected, opt => opt.IgnoringCyclicReferences());
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_DoesntAugmentsGeneratedClaimsWhenNameIdIsMissing()
        {
            var context = OwinTestHelpers.CreateOwinContext();

            string[] specifiedAuthTypes = null;

            context.Set<AuthenticateDelegate>("security.Authenticate",
                (authTypes, callback, state) =>
                {
                    specifiedAuthTypes = authTypes;
                    callback(new ClaimsIdentity(new Claim[]
                        {
                            new Claim(Saml2ClaimTypes.SessionIndex, "SessionId", null, "http://idp.example.com"),
                            new Claim(ClaimTypes.Role, "SomeRole", null, "http://idp.example.com")
                        }, "Federation"),
                        new Dictionary<string, string>(),
                        new Dictionary<string, object>(),
                        state);
                    return Task.FromResult(0);
                });

            var options = new Saml2AuthenticationOptions(true);

            var subject = new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(303, grant: new AuthenticationResponseGrant(
                    new ClaimsIdentity(new Claim[]
                    {
                        new Claim(ClaimTypes.NameIdentifier, "ApplicationNameId")
                    }, "ApplicationIdentity"), new AuthenticationProperties())),
                CreateAppBuilder(),
                options);

            await subject.Invoke(context);

            specifiedAuthTypes.Should().HaveCount(1)
                .And.Subject.Single().Should().Be(DefaultSignInAsAuthenticationType);

            var expected = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.NameIdentifier, "ApplicationNameId"),
            }, "ApplicationIdentity");

            context.Authentication.AuthenticationResponseGrant.Identity
                .Should().BeEquivalentTo(expected, opt => opt.IgnoringCyclicReferences());
        }

        [TestMethod]
        public void Saml2AuthenticationMiddleware_LogsCommandExceptions()
        {
            var context = OwinTestHelpers.CreateOwinContext();
            context.Request.Path = new PathString("/Saml2/SignIn");
            context.Request.QueryString = new QueryString("idp=incorrect");

            var options = new Saml2AuthenticationOptions(true);
            options.SPOptions.Logger = Substitute.For<ILoggerAdapter>();

            var subject = new Saml2AuthenticationMiddleware(
                null,
                CreateAppBuilder(),
                options);

            subject.Awaiting(async s => await s.Invoke(context)).Should().Throw<InvalidOperationException>();

            options.SPOptions.Logger.Received().WriteError(
                "Error in Saml2 for /Saml2/SignIn", Arg.Any<Exception>());
        }

        [TestMethod]
        public void Saml2AuthenticationMiddleware_Ctor_NullCheckOptionsSpOptions()
        {
            var options = new Saml2AuthenticationOptions(false);

            Action a = () => new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(404),
                CreateAppBuilder(),
                options);

            a.Should().Throw<ConfigurationErrorsException>()
                .WithMessage("The options.SPOptions property cannot be null. There is an implementation class Sustainsys.Saml2.Configuration.SPOptions that you can instantiate. The EntityId property of that class is mandatory. It must be set to the EntityId used to represent this system.");
        }

        [TestMethod]
        public void Saml2AuthenticationMiddleware_Ctor_NullCheckOptionsSpOptionsEntityId()
        {
            var options = new Saml2AuthenticationOptions(false)
            {
                SPOptions = new SPOptions()
            };

            Action a = () => new Saml2AuthenticationMiddleware(
                new StubOwinMiddleware(404),
                CreateAppBuilder(),
                options);

            a.Should().Throw<ConfigurationErrorsException>()
                .WithMessage("The SPOptions.EntityId property cannot be null. It must be set to the EntityId used to represent this system.");

        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_IncludesSamlResponseInLoggedError()
        {
            var context = OwinTestHelpers.CreateOwinContext();

            context.Request.Path = new PathString("/Saml2/Acs");
            context.Request.Method = "POST";

            var response = "<DummyXml />";

            var bodyData = new KeyValuePair<string, string>[] {
                new KeyValuePair<string, string>("SAMLResponse",
                    Convert.ToBase64String(Encoding.UTF8.GetBytes(response))),
            };

            var encodedBodyData = new FormUrlEncodedContent(bodyData);

            context.Request.Body = encodedBodyData.ReadAsStreamAsync().Result;
            context.Request.ContentType = encodedBodyData.Headers.ContentType.ToString();

            var options = new Saml2AuthenticationOptions(true);
            options.SPOptions.Logger = Substitute.For<ILoggerAdapter>();

            var subject = new Saml2AuthenticationMiddleware(
                null,
                CreateAppBuilder(),
                options);

            await subject.Invoke(context);

            options.SPOptions.Logger.Received().WriteError(
                "Saml2 Authentication failed. The received SAML data is\n<DummyXml />",
                Arg.Any<BadFormatSamlResponseException>());
        }

        [TestMethod]
        public async Task Saml2AuthenticationMiddleware_LogsErrorWhenNoSamlResponseIsAvailable()
        {
            var context = OwinTestHelpers.CreateOwinContext();

            context.Request.Path = new PathString("/Saml2/Acs");
            context.Request.Method = "POST";

            var options = new Saml2AuthenticationOptions(true);
            options.SPOptions.Logger = Substitute.For<ILoggerAdapter>();

            var subject = new Saml2AuthenticationMiddleware(
                null,
                CreateAppBuilder(),
                options);

            await subject.Invoke(context);

            options.SPOptions.Logger.Received().WriteError(
                "Saml2 Authentication failed.",
                Arg.Any<NoSamlResponseFoundException>());
        }
    }
}
