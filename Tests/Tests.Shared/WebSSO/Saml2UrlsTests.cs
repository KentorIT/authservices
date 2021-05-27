using System;
using System.Collections.Specialized;
using System.Web;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Sustainsys.Saml2.Configuration;
using FluentAssertions;
using Sustainsys.Saml2.WebSso;
using NSubstitute;
using Sustainsys.Saml2.TestHelpers;

namespace Sustainsys.Saml2.Tests.WebSso
{
    [TestClass]
    public class Saml2UrlsTests
    {
        [TestMethod]
        public void Saml2Urls_Ctor_NullCheckRequest()
        {
            Action a = () => new Saml2Urls(null, new Options(new SPOptions()));

            a.Should().Throw<ArgumentNullException>().And.ParamName.Should().Be("request"); ;
        }

        [TestMethod]
        public void Saml2Urls_Ctor_NullCheckOptions()
        {
            Action a = () => new Saml2Urls(
                new HttpRequestData("GET", new Uri("http://localhost")),
                null);

            a.Should().Throw<ArgumentNullException>().And.ParamName.Should().Be("options");
        }

        [TestMethod]
        public void Saml2Urls_Ctor_NullCheckApplicationUrl()
        {
            Action a = () => new Saml2Urls(null, "modulePath");

            a.Should().Throw<ArgumentNullException>().And.ParamName.Should().Be("applicationUrl");
        }

        [TestMethod]
        public void Saml2Urls_Ctor_NullCheckModulePath()
        {
            Action a = () => new Saml2Urls(new Uri("http://localhost"), modulePath: null);

            a.Should().Throw<ArgumentNullException>("modulePath");
        }

        [TestMethod]
        public void AuthServiecsUrls_Ctor_HandlesApplicationNotInRoot()
        {
            var appUrl = new Uri("http://localhost:73/SomePath");
            var modulePath = "/modulePath";

            var subject = new Saml2Urls(appUrl, modulePath);

            subject.AssertionConsumerServiceUrl.Should().Be(new Uri("http://localhost:73/SomePath/modulePath/Acs"));
            subject.SignInUrl.Should().Be(new Uri("http://localhost:73/SomePath/modulePath/SignIn"));
        }

        [TestMethod]
        public void Saml2Urls_Ctor_HandlesApplicationInRoot()
        {
            var appUrl = new Uri("http://localhost:42/");
            var modulePath = "/modulePath";

            var subject = new Saml2Urls(appUrl, modulePath);

            subject.AssertionConsumerServiceUrl.Should().Be(new Uri("http://localhost:42/modulePath/Acs"));
            subject.SignInUrl.Should().Be(new Uri("http://localhost:42/modulePath/SignIn"));
        }

        [TestMethod]
        public void Saml2Urls_Ctor_ChecksModulePathStartsWithSlash()
        {
            var appUrl = new Uri("http://localhost:42");
            var modulePath = "modulePath";

            Action a = () => new Saml2Urls(appUrl, modulePath);

            a.Should().Throw<ArgumentException>("modulePath should start with /.");
        }

        [TestMethod]
        public void Saml2Urls_Ctor_EnsuresApplicationUrlEndsWithSlash()
        {
            var request = new HttpRequestData(
                "GET",
                new Uri("http://localhost:1234/Foo/Bar"),
                "/Foo",
                null,
                null,
                null);

            var options = StubFactory.CreateOptions();
            var subject = new Saml2Urls(request, options);
            subject.ApplicationUrl.OriginalString.Should().EndWith("/");
        }

        [TestMethod]
        public void AuthServiecsUrls_Ctor_AcceptsFullUrls()
        {
            var acsUrl = new Uri("http://localhost:73/MyApp/MyAcs");
            var signinUrl = new Uri("http://localhost:73/MyApp/MySignin");
            var appUrl = new Uri("http://localhost:73/MyApp");
            var logoutUrl = new Uri("http://localhost:73/MyApp/MyLogout");

            var subject = new Saml2Urls(acsUrl, signinUrl, appUrl, logoutUrl);

            subject.AssertionConsumerServiceUrl.ToString().Should().Be(acsUrl.ToString());
            subject.SignInUrl.ToString().Should().Be(signinUrl.ToString());
            subject.ApplicationUrl.Should().Be(appUrl.ToString());
            subject.LogoutUrl.Should().Be(logoutUrl.ToString());
        }

        [TestMethod]
        public void Saml2Urls_Ctor_AllowsNullAcs()
        {
            // AssertionConsumerServiceURL is optional in the SAML spec 
            var subject = new Saml2Urls(null, new Uri("http://localhost/signin"), null, new Uri("http://localhost/logout"));

            subject.AssertionConsumerServiceUrl.Should().Be(null);
            subject.SignInUrl.ToString().Should().Be("http://localhost/signin");
            subject.LogoutUrl.ToString().Should().Be("http://localhost/logout");
        }

        [TestMethod]
        public void Saml2Urls_Ctor_NullCheckSignin()
        {
            Action a = () => new Saml2Urls(
                new Uri("http://localhost/signin"),
                signInUrl: null,
                applicationUrl: new Uri("http://localhost"),
                logoutUrl: null);

            a.Should().Throw<ArgumentNullException>("signInUrl");
        }

        [TestMethod]
        public void Saml2Urls_Ctor_PerRequest_PublicOrigin()
        {
            var options = StubFactory.CreateOptionsPublicOrigin(new Uri("https://my.public.origin:8443/"));
            options.Notifications.GetPublicOrigin = (requestData) =>
            {
                return new Uri("https://special.public.origin/");
            };
            var urls = new Saml2Urls(new HttpRequestData("get", new Uri("http://servername/")), options);
            urls.AssertionConsumerServiceUrl.Should().BeEquivalentTo(new Uri("https://special.public.origin/Saml2/Acs"));
            urls.SignInUrl.Should().BeEquivalentTo(new Uri("https://special.public.origin/Saml2/SignIn"));
        }
    }
}
