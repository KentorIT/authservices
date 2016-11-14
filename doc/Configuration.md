kentor.AuthServices Configuration
=============
To use Kentor.AuthServices in an application and configure it in web.config
(which is the default for the httpmodule and mvc libraries) it must be enabled 
in the application's `web.config`. The sample applications contains complete
working [`web.config`](../SampleApplication/Web.config) examples. For 
ASP.NET MVC applications see [`this working web.config`](../SampleMvcApplication/Web.config)
example. Applications using the owin library usually make their configuration
in code and in that case no web.config changes are needed. If an owin library
is set up to use web.config (by passing `true` to the `KentorAuthServicesAuthenticationOptions` 
constructor) the information here applies.

##Config Sections
Three new config sections are required. Add these under `configuration/configSections`:
```
<configSections>
  <!-- Add these sections below any existing. -->
  <section name="system.identityModel" type="System.IdentityModel.Configuration.SystemIdentityModelSection, System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=B77A5C561934E089" />
  <section name="system.identityModel.services" type="System.IdentityModel.Services.Configuration.SystemIdentityModelServicesSection, System.IdentityModel.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=B77A5C561934E089" />   
  <section name="kentor.authServices" type="Kentor.AuthServices.Configuration.KentorAuthServicesSection, Kentor.AuthServices"/>
</configSections>
```
##Loading modules
When using the http module and the MVC controller, the `SessionAuthenticationModule` needs
to be loaded and if using the http module that needs to be loaded as well. The owin package
does not need any http modules, please see the separate info on the [Owin middleware](OwinMiddleware.md).

```
<system.web>
  <httpModules>
	<!-- Add these modules below any existing. The SessionAuthenticatioModule
         must be loaded before the Saml2AuthenticationModule -->
    <add name="SessionAuthenticationModule" type="System.IdentityModel.Services.SessionAuthenticationModule, System.IdentityModel.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"/>
    <!-- Only add the Saml2AuthenticationModule if you're using the Kentor.AuthServices.HttpModule
		 library. If you are using Kentor.AuthServices.Mvc you SHOULD NOT load this module.-->
	<add name="Saml2AuthenticationModule" type="Kentor.AuthServices.HttpModule.Saml2AuthenticationModule, Kentor.AuthServices.HttpModule"/>
  </httpModules>
</system.web>
```

##kentor.authServices Section
The saml2AuthenticationModule section contains the configuration of the Kentor.AuthServices
library. It is required for the http module and the mvc controller. The Owin middleware Can
read web.config, but can also be configured from code.

```
<kentor.authServices entityId="http://localhost:17009"
                     returnUrl="http://localhost:17009/SamplePath/"
                     discoveryServiceUrl="http://localhost:52071/DiscoveryService" 
					 authenticateRequestSigningBehavior="Always">
  <nameIdPolicy allowCreate="true" format="Persistent"/>
  <metadata cacheDuration="0:0:42" validDuration="7.12:00:00" wantAssertionsSigned="true">
    <organization name="Kentor IT AB" displayName="Kentor" url="http://www.kentor.se" language="sv" />
    <contactPerson type="Other" email="info@kentor.se" />
    <requestedAttributes>
      <add friendlyName ="Some Name" name="urn:someName" nameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true" />
      <add name="Minimal" />
    </requestedAttributes>
  </metadata>
  <identityProviders>
    <add entityId="https://stubidp.kentor.se/Metadata" 
         signOnUrl="https://stubidp.kentor.se" 
         allowUnsolicitedAuthnResponse="true"
		 binding="HttpRedirect"
		 wantAuthnRequestsSigned="true">
      <signingCertificate storeName="AddressBook" storeLocation="CurrentUser" 
                          findValue="Kentor.AuthServices.StubIdp" x509FindType="FindBySubjectName" />
    </add>
    <add entityId="example-idp"
         metadataLocation="https://idp.example.com/Metadata"
         allowUnsolicitedAuthnResponse="true" 
         loadMetadata = "true" />
  </identityProviders>
  <!-- Optional configuration for signed requests. Required for Single Logout. -->
  <serviceCertificates>
    <add fileName="~/App_Data/Kentor.AuthServices.Tests.pfx" />
  </serviceCertificates>
  <!-- Optional configuration for fetching IDP list from a federation -->
  <federations>
    <add metadataLocation="https://federation.example.com/metadata.xml" allowUnsolicitedAuthnResponse = "false" />
  </federations>
</kentor.authServices>
```

###`<kentor.authServices>` Element
*Child element of `<configuration>` element.*

Root element of the config section.

####Attributes
* [`returnUrl`](#returnUrl-attribute)
* [`entityId`](#entityid-attribute)
* [`discoveryServiceUrl`](#discoveryserviceurl-attribute)
* [`modulePath`](#modulepath-attribute)
* [`authenticateRequestSigningBehavior`](#authenticaterequestsigningbehavior-attribute)
* [`validateCertificates`](#validatecertificates-attribute)
* [`publicOrigin`](#publicorigin-attribute)

####Elements
* [`<nameIdPolicy>`](#nameidpolicy-element)
* [`<requestedAuthnContext>`](#requestedauthncontext-element)
* [`<metadata>`](#metadata-element)
* [`<identityProviders>`](#identityproviders-element)
* [`<federations>`](#federations-element)
* [`<serviceCertificates>`](#servicecertificates-element)
* [`<compatibility>`](#compatibility-element)

####`entityId` Attribute
*Attribute of the [`<kentor.authServices>`](#kentor-authservices-section) element.*

The name that this service provider will use for itself when sending
messages. The name will end up in the `Issuer` field in outcoing authnRequests.

The SAML standard requires the `entityId` to be an absolute URI. Typically it should
be the URL where the metadata is presented. E.g.
`http://sp.example.com/AuthServices/`.

####`returnUrl` Attribute
*Attribute of the [`<kentor.authServices>`](#kentor-authservices-section) element.*

The Url that you want users to be redirected to once the authentication is
complete. This is typically the start page of the application, or a special
signed in start page.

####`discoveryServiceUrl` Attribute
*Optional Attribute of the [`<kentor.authServices>`](#kentor-authservices-section) element.*

Optional attribute that specifies an idp discovery service to use if no idp
is specified when calling sign in. Without this attribute, the first idp known
will be used if none is specified.

####`modulePath` Attribute
*Optional Attribute of the [`<kentor.authServices>`](#kentor-authservices-section) element.*

Optional attribute that indicates the base path of the AuthServices endpoints.
Defaults to `/AuthServices` if not specified. This can usually be left as the
default, but if several instances of AuthServices are loaded into the
same process they must each get a separate base path.

####`authenticateRequestSigningBehavior` Attribute
*Optional Attribute of the [`<kentor.AuthServices>`](#kentor-authservices-section) element.*

Optional attribute that sets the signing behavior for generated AuthnRequests.
Two values are supported:

* `Never`: AuthServices will never sign any
  created AuthnRequests.
* `Always`: AuthServices will always sign all AuthnRequests.
* `IfIdpWantAuthnRequestsSigned` (default if the attribute is missing):
  AuthServices will sign AuthnRequests if the idp is configured for it (through
  config or listed in idp metadata).

####`validateCertificates` Attribute
*Optional Attribute of the [`<kentor.authServices>`](#kentor-authservices-section) element.*

Normally certificates for the IDPs signing use is communicated through metadata
and in case of a breach, the metadata is updated with new data. If you want
extra security, you can enable certificate validation. Please note that the 
SAML metadata specification explicitly places no requirements on certificate
validation, so don't be surprised if an Idp certificate doesn't pass validation.

####`publicOrigin` Attribute
*Optional Attribute of the [`<kentor.authServices>`](#kentor-authservices-section) element.*

Optional attribute that indicates the base url of the AuthServices endpoints.
It should be the root path of the application. E.g. The SignIn url is built
up as PublicOrigin + / + modulePath + /SignIn.

Defaults to `Url` of the current http request if not specified. This can usually 
be left as the default, but if your internal address of the application is 
different than the external address the generated URLs (such as  `AssertionConsumerServiceURL` 
in the `saml2p:AuthnRequest`) will be incorrect. The use case for this is typically 
with load balancers or reverse proxies. It can also be used if the application
can be accessed by several external URLs to make sure that the registered in
metadata is used in communication with the Idp.

###`<nameIdPolicy>` Element
*Optional child element of the [`<kentor.authServices>`](#kentor-authservices-section) element.*

Controls the generation of NameIDPolicy element in AuthnRequests. The element Is
only created if either `allowCreate` or `format` are set to a non-default value.

####Attributes
* [`allowCreate`](#allowcreate-attribute)
* [`format`](#format-attribute)

####`allowCreate` Attribute
*Optional attribute of the [`nameIdPolicy`](#nameidpolicy-element) element.*

Default value is empty, which means that the attribute is not included in
generated AuthnRequests.

Supported values are `true` or `false`.

####`format` Attribute
*Optional attribute of the [`nameIdPolicy`](#nameidpolicy-element) element.*

Sets the requested format of NameIDPolicy for generated authnRequests.

Supported values (see section 8.3 in the SAML2 Core specification for
explanations of the values).

* `Unspecified`
* `EmailAddress`
* `X509SubjectName`
* `WindowsDomainQualifiedName`
* `KerberosPrincipalName`
* `EntityIdentifier`
* `Persistent`
* `Transient`

If no value is specified, no format is specified in the generated AuthnRequests.

If `Transient` is specified, it is not permitted to specify `allowCreate` 
(see 3.4.1.1 in the SAML2 Core spec).

###`<requestedAuthnContext>` element
*Optional child element of the [`<kentor.authServices>`](#kentor-authservices-section) element.*

####Attributes
* [`classRef`](#classref-attribute)
* [`comparison`](#comparison-attribute)

####`classRef` attribute
*Optional attribute of the [`requestedAuthnContext`](#requestedauthncontext-element) element.*

Class reference for authentication context. Either specify a full URI to identify
an authentication context class, or a single word if using one of the predefined
classes in the SAML2 Authentication context specification:

* `InternetProtocol`
* `InternetProtocolPassword`
* `Kerberos`
* `MobileOneFactorUnregistered`
* `MobileTwoFactorUnregistered`
* `MobileOneFactorContract`
* `MobileTwoFactorContract`
* `Password`
* `PasswordProtectedTransport`
* `PreviousSession`
* `X509`
* `PGP`
* `SPKI`
* `XMLDSig`
* `Smartcard`
* `SmartcardPKI`
* `SoftwarePKI`
* `Telephony`
* `NomadTelephony`
* `PersonalTelephony`
* `AuthenticatedTelephony`
* `SecureRemotePassword`
* `TLSClient`
* `TimeSyncToken`
* `unspecified`

####`comparison` Attribute
*Optional attribute of the [`requestedAuthnContext`](#requestedauthncontext-element) element.*

Comparison method for authentication context as signalled in AuthnRequests.

Valid values are:
* `Exact` (default)
* `Minimum`
* `Maximum`
* `Better`

`Minimum` is an inclusive comparison, meaning the specified classRef or anything
better is accepted. `Better` is exclusive, meaning that the specified classRef
is not accepted.

###`<metadata>` Element
*Optional child element of the [`<kentor.authServices>`](#kentor-authservices-section) element.*

The metadata part of the configuration can be used to tweak the generated
metadata. These configuration options only affects how the metadata is
generated, no other behavior of the code is changed.

####Attributes
* [`cacheDuration`](#cacheduration-attribute)
* [`validDuration`](#validduration-attribute)
* [`wantAssertionsSigned`](#wantassertionssigned-attribute)

####Elements
* [`<organization>`](#organization-element)
* [`<contactPerson>`](#contactperson-element)
* [`<requestedAttributes>`](#requestedattributes-element)

####`cacheDuration` Attribute
*Optional attribute of the [`<metadata>`](#metadata-element) element.*

Optional attribute that describes for how long in anyone should cache the 
metadata presented by the service provider before trying to fetch a new copy.
Defaults to one hour. Examples of valid format strings:

* 1 day, 2 hours: `1.2:00:00`.
* 42 seconds: `0:00:42`.

####`validDuration` Attribute
*Optional attribute of the [`<metadata>`](#metadata-element) element.*

Optional attribute that sets the maximum time that anyone may cache the generated
metadata. if cacheDuration is specified, the remote party should try to reload
metadata after that time. If that refresh fails, validDuration determines for
how long the old metadata may be used before it must be discarded.

In the metadata, the time is exposed as an absolute validUntil date and time.
That absolute time is calculated on metadata generation by adding the configured
validDuration to the current time. Examples of valid format strings:

* 1 day, 2 hours: `1.2:00:00`.
* 42 seconds: `0:00:42`.

####`wantAssertionsSigned` Attribute
*Optional attribute of the [`<metadata>`](#metadata-element) element.*

Optional attribute to signal to IDPs that we want the Assertions themselves 
signed and not only the SAML response. AuthServices supports both, so for
normal usage this shouldn't matter. If set to `false` the entire 
`wantAssertionsSigned` attribute is dropped from the metadata as the default
values is false.

###`<organization>` Element
*Optional child element of the [`<metadata>`](#metadata-element) element.*

Provides information about the organization supplying the SAML2 entity (in plain
English that means the organization that supplies the application that AuthServices
is used in).

####Attributes
* [`name`](#name-attribute-organization)
* [`displayName`](#displayname-attribute)
* [`url`](#url-attribute)
* [`langauge`](#language-attribute)

####`name` Attribute (organization)
*Attribute of the [`<organization>`](#organization-element) element.*

The name of the organization.

####`displayName` Attribute
*Attribute of the [`<organization>`](#organization-element) element.*

The display name of the organization.

####`url` Attribute
*Attribute of the [`<organization>`](#organization-element) element.*

Url to the organization's web site.

####`language` Attribute
*Optional Attribute of the [`<organization>`](#organization-element) element.*

In the generated metadata, the `name`, `displayName` and `url` attributes have
a language specification. If none is specified, the `xml:lang` attribute will
be generated with an empty value.

###`<contactPerson>` Element
*Optional child element of the [`<metadata>`](#metadata-element) element. Can
be repeated multiple times.*

####Attributes
* [`type`](#type-attribute)
* [`company`](#company-attribute)
* [`givenName`](#givenname-attribute)
* [`surname`](#surname-attribute)
* [`phoneNumber`](#phonenumber-attribute)
* [`email`](#email-attribute)

####`type` Attribute
*Attribute of the [`<contactPerson>`](#contactperson-element) element.*

The type attribute indicates the type of the contact and is picked from the
[`ContactType`](http://msdn.microsoft.com/en-us/library/system.identitymodel.metadata.contacttype(v=vs.110).aspx) 
enum. Valid values are:

* Administrative
* Billing
* Other
* Support
* Technical

####`company` Attribute
*Optional attribute of the [`<contactPerson>`](#contactperson-element) element.*

Name of the person's company.

####`givenName` Attribute
*Optional attribute of the [`<contactPerson>`](#contactperson-element) element.*

Given name of the person.

####`surname` Attribute
*Optional attribute of the [`<contactPerson>`](#contactperson-element) element.*

Surname of the person.

####`phoneNumber` Attribute
*Optional attribute of the [`<contactPerson>`](#contactperson-element) element.*

Phone number of the person. The SAML standard allows multiple phone number to
be specified. AuthServices supports that, but not through the configuration file.

####`email` Attribute
*Optional attribute of the [`<contactPerson>`](#contactperson-element) element.*

Email address of the person. The SAML standard allows multiple email addresses to
be specified. AuthServices supports that, but not through the configuration file.

###`<requestedAttributes>` Element
*Optional child element of the [`<metadata>`](#metadata-element) element.*

List of attributes that the SP requests to be included in the assertions 
generated by an identity provider.

Each attribute is added to the list with an `<add>` element.

####Attributes of the `<add>` element for `<requestedAttributes>`
* [`name`](#name-attribute-requestedattribute)
* [`friendlyName`](#friendlyname-attribute)
* [`nameFormat`](#nameformat-attribute)
* [`isRequired`](#isrequired-attribute)

####`name` Attribute (RequestedAttribute)
*Attribute of `<add>` for []`<requestedAttributes>`](requestedattributes-element)*

The name of the attribute. This is usually in the form of an urn/oid, e.g. 
urn:oid:1.2.3. The format of hte name should be specified in the 
[`nameFormat`](#nameformat-attribute) attribute.

####`friendlyName` Attribute
*Optional Attribute of `<add>` for []`<requestedAttributes>`](requestedattributes-element)*

An optional friendly (i.e. human readable) friendly name of the attribute that
will be included in the metadata. Please note that the SAML2 standard specifically
forbids the `friendlyName` to be used for anything else an information to a human.
All matching of attributes must use the `name`.

####`nameFormat` Attribute
*Optional Attribute of `<add>` for []`<requestedAttributes>`](requestedattributes-element)*

Format of the name attribute. Valid values are:

* urn:oasis:names:tc:SAML:2.0:attrname-format:uri
* urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified
* urn:oasis:names:tc:SAML:2.0:attrname-format:basic

####`isRequired` Attribute
*Optional Attribute of `<add>` for []`<requestedAttributes>`](requestedattributes-element)*

Is this attribute required by the service provider or is it just a request that
it would be nice if the Idp includes it?

###`<identityProviders>` Element
*Optional child element of the [`<kentor.authServices>`](#kentor-authservices-section) element.*

A list of identity providers known to the service provider.

####Elements
* [`<add>`](#add-identityprovider-element)

###`<add>` IdentityProvider Element
*Child element of the [`<identityProviders`](#identityproviders-element) element.*

####Attributes
* [`entityID`](#entityId-attribute-identityprovider)
* [`signOnUrl`](#signonurl-attribute)
* [`logoutUrl`](#logouturl-attribute)
* [`allowUnsolicitedAuthnResponse`](#allowunsolicitedauthnresponse-attribute)
* [`binding`](#binding-attribute)
* [`wantAuthnRequestsSigned`](#wantauthnrequestssigned-attribute)
* [`loadMetadata`](#loadmetadata-attribute)
* [`metadataLocation`](#metadataLocation-attribute-idp)
* [`disableOutboundLogoutRequests`](disableOutboundLogoutRequests-attribute)

####Elements
* [`<signingCertificate>`](#signingcertificate-element)

####`entityId` Attribute (identityProvider)
*Attribute of the [`<add>`](#add-identityprovider-element) element*

The issuer name that the idp will be using when sending responses. When `<loadMetadata>`
is enabled, the `entityId` is treated as a URL to for downloading the metadata.

####`signOnUrl` Attribute
*Optional attribute of the [`<add>`](#add-identityprovider-element) element*

The url where the identity provider listens for incoming sign on requests. The 
url has to be written in a way that the client understands, since it is
the client web browser that will be redirected to the url. Specifically
this means that using a host name only url or a host name that only resolves
on the network of the server won't work.

####`logoutUrl` Attribute
*Optional attribute of the [`<add>`](#add-identityprovider-element) element*

The url where the identity provider listens for incoming logout requests and
responses. To enable single logout behaviour there must also be a service
certificate configured in AuthServices as all logout messages must be signed.

####`allowUnsolicitedAuthnResponse` Attribute
*Attribute of the [`<add>`](#add-identityprovider-element) element*

Allow unsolicited responses. That is, Idp initiated sign on where there was no
prior AuthnRequest. 
If `true` InResponseTo is not required and the IDP can initiate the authentication
process. If `false` InResponseTo is required and the authentication process must
be initiated by an AuthnRequest from this SP. 
Note that if the authentication was SP-intiatied, RelayState and InResponseTo
must be present and valid.

####`binding` Attribute
*Optional attribute of the [`<add>`](#add-identityprovider-element) element*

The binding that the services provider should use when sending requests
to the identity provider. One of the supported values of the `Saml2BindingType`
enum.

Currently supported values:

* `HttpRedirect`
* `HttpPost`

####`wantAuthnRequestsSigned` attribute
*Optional attribute of the [`<add>`](#add-identityprovider-element) element*

Specifies whether the Identity provider wants the AuthnRequests signed.
Defaults to `false`.

####`loadMetadata` Attribute
*Optional attribute of the [`<add>`](#add-identityprovider-element) element*

Load metadata from the idp and use that information instead of the configuration. It is
possible to use a specific certificate even though the metadata is loaded, in that case
the configured certificate will take precedence over any contents in the metadata.

####`metadataLocation` Attribute (Idp)
*Optional attribute of the [`add`](#add-identityprovider-element) element*

The SAML2 metadata standard strongly suggests that the Entity Id of a SAML2 entity
is a URL where the metadata of the entity can be found. When loading metadata
for an idp, AuthServices normally interprets the EntityId as a url to the metadata.
If the metadata is located somewhere else it can be specified with this
configuration parameter. The location can be a URL, an absolute path to a local
file or an app relative path (e.g. ~/App_Data/IdpMetadata.xml)

####`disableOutboundLogoutRequests` Attribute
*Optional attribute of the [`add`](#add-identityprovider-element) element*

Disable outbound logout requests to this idp, even though AuthServices is
configured for single logout and the idp supports it. This setting might be
usable when adding SLO to an existing setup, to ensure that everyone is ready
for SLO before activating.

###`<signingCertificate>` Element
*Optional child element of the [`<identityProvider>`](#identityprovider-element) element*

The certificate that the identity provider uses to sign its messages. The 
certificate can either be loaded from file if the `fileName` attribute is
specified or from a certificate store if the other attributes are specified.
If a `fileName` is specified that will take precedence and the other attributes
will be ignored.

###Attributes
* [`fileName`](#filename-attribute)
* [`storeName`](#storename-attribute)
* [`storeLocation`](#storelocation-attribute)
* [`findValue`](#findvalue-attribute)
* [`x509FindType`](#x509findtype-attribute)

####`fileName` Attribute
*Attribute of the [`<signingCertificate>`](#signingcertificate-element) element*

A file name to load the certificate from. The path is relative to the execution
path of the application.

File based certificates are only recommended for testing and during 
development. In production environments it is better to use the certificate
storage.

####`storeName` Attribute
*Attribute of the [`<signingCertificate>`](#signingcertificate-element) element*

Name of the certificate store to search for the certificate. It is recommended
to keep the certificate of the identity provider in the "Other People" store
which is specified by the `AddressBook` enum value.

Valid values are those from the 
[`System.Security.Cryptography.X509Certificates.StoreName`](http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.storename.aspx)
enumeration.

####`storeLocation` Attribute
*Attribute of the [`<signingCertificate>`](#signingcertificate-element) element*

The location of the store to search for the certificate. On production services
it is recommended to use the `LocalMachine` value, while it makes more sense
to use `CurrentUser` in development setups.

Valid values are those from the
[`System.Security.Cryptography.X509Certificates.StoreLocation`](http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.storelocation.aspx)
enumeration.

####`findValue` Attribute
*Attribute of the [`<signingCertificate>`](#signingcertificate-element) element*

A search term to use to find the certificate. The value will be searched for in
the field specified by the [`x509FindType`](#x509findtype-attribute) attribute.

####`x509FindType` Attribute
*Attribute of the [`<signingCertificate>`](#signingcertificate-element) element*

The field that will be seach for a match to the value in 
[`findValue`](#findvalue-attribute). For security, it is recommended to use 
`FindBySerialNumber`.

*Note: There is a nasty bug when copying a serial number from the certificate info 
displayed by certificate manager and the browser. There is a hidden character 
before the first hex digit that will mess upp the matching. Once pasted into
the config, use the arrow keys to make sure that there is not an additional
invisible character at the start of the serial number string.*

Valid values are those from the
[`System.Security.Cryptography.X509Certificates.X509FindType`](http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509findtype.aspx)
enumeration.

###`<federations>` Element
*Optional child element of the `<kentor.authServices>`(#kentor-authservices-section) element.*

Contains a list of federations that the service provider knows and trusts.

####Elements
* [`<add>`](#add-federation-element).

###`<add>` Federation Element
* Child element of the `<federations>`(#federations-element) element.*

Adds a known federation.

####Attributes
* [`metadataLocation`](#metadataLocation-attribute-federation).
* [`allowUnsolicitedAuthnResponse`](#allowunsolicitedauthnresponse-attribute-federation)

####`metadataLocation` Attribute (Federation)
*Attribute of [`<add>`](#add-federation-element)*

URL to the full metadata of the federation. AuthServices will download the
metadata and add all identity providers found to the list of known and trusted
identity providers. The location can be a URL, an absolute path to a local
file or an app relative path (e.g. ~/App_Data/IdpMetadata.xml)


####`allowUnsolicitedAuthnResponse` Attribute (Federation)
*Attribute of [`<add>`](#add-federation-element)*

Decided whether unsolicited authn responses should be allowed from the identity providers
in the federation.

###`<serviceCertificates>` Element
*Optional child element of the [`<kentor.authServices>`](#kentorauthservices-section) element.*

Specifies the certificate(s) that the service provider uses for encrypted assertions
(and for signed requests, once that feature is added).

If neither of those features are used, this element can be ommitted.

The public key(s) will be exposed in the metadata and the private
key(s) will be used during decryption/signing. 


####Elements
* [`<add>`](#add-servicecertificate-element).

Add a service certificate

###`<add>` ServiceCertificate Element

Uses same options/attributes as [`<signingCertificate>`](#signingcertificate-element) for locating the certificate.
But also has the below options for configuring how the certificate will be used.

####Attributes
* [`use`](#use-attribute-servicecertificate)
* [`status`](#status-attribute-servicecertificate)
* [`metadataPublishOverride`](#metadatapublishoverride-attribute-servicecertificate)

####`use` Attribute (ServiceCertificate)
* Optional attribute of [`<add>`](#add-servicecertificate-element).*

How should this certificate be used? 
Options are:
 * Signing
 * Encryption
 * Both (Default)

####`status` Attribute (ServiceCertificate)
* Optional attribute of [`<add>`](#add-servicecertificate-element).*

Is this certificate for current or future use (i.e. key rollover scenario)? 
Options are:
 * Current (Default)
 * Future

####`metadataPublishOverride` Attribute (ServiceCertificate)
* Optional attribute of [`<add>`](#add-servicecertificate-element).*

Should we override how this certificate is published in the metadata? 
Options are:
 * None (Default) - published according to the rules in the table below.
 * PublishUnspecified
 * PublishEncryption
 * PublishSigning
 * DoNotPublish

Use | Status | Published in Metatadata | Used by AuthServices
------------ | ------------- | ------------- | ------------- | -------------
Both | Current | Unspecified _unless Future key exists_, then Signing | Yes 
Both | Future | Unspecified | For decryption only 
Signing | Current | Signing | Yes 
Signing | Future | Signing | No 
Encryption | Current | Encryption _unless Future key exists_ then not published | Yes 
Encryption | Future | Encryption | Yes 

###`</compatibility>` Element
*Optional child element of the [`<kentor.authServices>`](#kentorauthservices-section) element.*

Enables overrides of default behaviour to increase compatibility with identity
providers.

####Attributes
* [`unpackEntitiesDescriptorInIdentityProviderMetadata`](#unpackentitiesdescriptorinidentityprovidermetadata-attribute)
* [`acceptOneTimeUseAssertions`](#acceptonetimeuseassertions-attribute)

####`unpackEntitiesDescriptorInIdentityProviderMetadata` Attribute
* Optional attribute of [`unpackEntitiesDescriptorInIdentityProviderMetadata`](#unpackentitiesdescriptorinidentityprovidermetadata-attribute)*

If an EntitiesDescriptor element is found when loading metadata for an
IdentityProvider, automatically check inside it if there is a single
EntityDescriptor and in that case use it.

####`unpackEntitiesDescriptorInIdentityProviderMetadata` Attribute
* Optional attribute of [`acceptOneTimeUseAssertions`](#acceptonetimeuseassertions-attribute)*

If a received SamlResponse is for one time use (Assertion/Conditions/OneTimeUse)
this will allow it to be used for WebSSO.

##`<system.identityModel>` Section
*Child element of `<configuration>` element.*

There must be a [`<system.identityModel>`](http://msdn.microsoft.com/en-us/library/hh568638.aspx)
section in the config file or there will be a runtime error. The section can 
be empty (use `<system.identityModel />`).

```
<system.identityModel>
  <identityConfiguration>
    <claimsAuthenticationManager type="Kentor.AuthServices.Tests.ClaimsAuthenticationManagerStub, Kentor.AuthServices.Tests"/>
  </identityConfiguration>
</system.identityModel>
```

###`<claimsAuthenticationManager>` Element
*Child element of the `<identityConfiguration>` element.*

Specifies the type of a custom [`ClaimsAuthenticationManager`](ClaimsAuthenticationManager.md) for the 
application. The default implementation just passes through the identity.


###`<system.IdentityModelServices>` Section
*Child element of `<configuration>` element.*

The [`<system.identityModel.services>`](http://msdn.microsoft.com/en-us/library/hh568674.aspx)
element configures the built in servies. For testing on non ssl sites, the
requirement for ssl for the session authentication cookie must be disabled.

***Note: It is a severe security risk to leave the `requireSsl` setting as 
`false` in a production environment.***

```
<system.identityModel.services>
  <federationConfiguration>
    <cookieHandler requireSsl ="false"/>
  </federationConfiguration>
</system.identityModel.services>
```
