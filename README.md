[![Build status](https://ci.appveyor.com/api/projects/status/kf9r7lh4mh28rg2d?branch=master&svg=true&passingText=master%20-%20OK&failingText=master%20-%20Failed!&pendingText=master%20-%20Pending...)](https://ci.appveyor.com/project/Sustainsys/Saml2)
[![Coverage Status](https://coveralls.io/repos/github/Sustainsys/Saml2/badge.svg?branch=master)](https://coveralls.io/github/Sustainsys/Saml2?branch=master)
[![Join the chat at https://gitter.im/Susatinsys/Saml2](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/Sustainsys/Saml2)
Sustainsys.Saml2
=============

The Sustainsys.Saml2 library adds SAML2P support to ASP.NET web sites, allowing the web site
to act as a SAML2 Service Provider (SP).
The library is undergoing a rename from the former name Kentor.AuthServices.

Kentor.AuthServices is open sourced and contributions are welcome, please see 
[contributing guidelines](CONTRIBUTING.md) for info on coding standards etc.

## Using
The AuthServices library can be used through three different ways:

* An Http Module, loaded into the IIS pipeline. The module is compatible with ASP.NET web 
forms sites.
* An ASP.NET MVC Controller for better integration and error handling in ASP.NET Applications.
* An Owin Middleware to use with the Owin Pipeline or for integration with ASP.NET Identity.

Note that this last usage scenario enables SAML identity providers to be integrated within
[IdentityServer3](https://github.com/IdentityServer/IdentityServer3) package.  Review [this document](doc/IdentityServer3Okta.md) to see how to configure AuthServices
with IdentityServer3 and Okta to add Okta as an identity provider to an IdentityServer3 project. There is also a SampleIdentityServer3 project in the AuthServices repository.

There are four nuget packages available. The core 
[Kentor.AuthServices](https://www.nuget.org/packages/Kentor.AuthServices/) contains the core
functionality. The [Kentor.AuthServices.HttpModule](https://www.nuget.org/packages/Kentor.AuthServices.HttpModule/)
contains an IIS Http Module (previously this was included in the core package). 
The [Kentor.AuthServices.Mvc](https://www.nuget.org/packages/Kentor.AuthServices.Mvc/)
package contains the MVC controller and the [Kentor.AuthServices.Owin](https://www.nuget.org/packages/Kentor.AuthServices.Owin/)
package contains the Owin middleware.

Once the nuget packages are installed you must provide configuration either through code
or through `web.config` sections.
See [configuration](doc/Configuration.md) for details.

## Troubleshooting

* Check the [issues archive](https://github.com/KentorIT/authservices/issues).
* Check the [SAML2 specification](http://saml.xml.org/saml-specifications), starting with the core section.
* Log your actual SAML2 conversation with [SAML Chrome Panel](https://chrome.google.com/webstore/detail/saml-chrome-panel/paijfdbeoenhembfhkhllainmocckace) or [SAML Tracer for Firefox](https://addons.mozilla.org/sv-se/firefox/addon/saml-tracer/).
* Connect an `ILoggerAdapter` to your `SPOptions.Logger`. If you are using the OWIN middleware this is done for you automatically and you can see the output in the OWIN/Katana logging.
* Last but not least, download the AuthServices source and check out what's really happening.

## Saml2AuthenticationModule
The Saml2AuthenticationModule is modeled after the WSFederationAuthenticationModule
to provide Saml2 authentication to IIS web sites. In many cases it should just be
[configured](doc/Configuration.md) in and work without any code written in the application 
at all (even though [providing an own ClaimsAuthenticationManager](doc/ClaimsAuthenticationManager.md)
for claims translation is highly recommended).

## Mvc Controller
The MVC package contains an MVC controller that will be accessible in your application just
by installing the package in the application. For MVC applications a controller is preferred
over using the authentication module as it integrates with MVC's error handling.

## Owin Middleware
The Owin middleware is modeled after the external authentication modules for social login
(such as Google, Facebook, Twitter). This allows easy integration with ASP.NET Identity 
for keeping application specific user and role information. See the 
[Owin Middleware](doc/OwinMiddleware.md) page for information on how to set up and use the middleware.

## Stub Idp
The solution also contains a stub (i.e. dummy) identity provider that can be used for testing.
Download the solution, or use the instance that's provided for free at http://stubidp.kentor.se.

## Protocol Classes
The protocol handling classes are available as a public API as well, making it possible to 
reuse some of the internals for writing your own service provider or identity provider.


## FIPS Compliance
The default encryption algorithm used is RijndaelManaged, while available everywhere, is not fips compliant.
To use the the compliant AesCryptoServiceProvider, see the [FIPS Configuration](doc/FipsConfiguration.md) page for information on
how to switch to using fips compliant algorithms.