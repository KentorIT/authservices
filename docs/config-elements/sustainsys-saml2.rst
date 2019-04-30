``<sustainsys.saml2>`` Element
==============================
The ``<sustainsys.saml2>`` element is a child node of the ``<configuration>`` element.  Its
attributes are listed and described below, and its child elements are listed as well and 
are linked to full explanations of each.

Attributes
----------
``returnUrl``
    The Url that you want users to be redirected to once the authentication is complete. This is typically the start 
    page of the application, or a special signed in start page.

``entityId``
    The name that this service provider will use for itself when sending messages. The name will end up in the ``Issuer`` 
    field in outcoing authnRequests.
    
    The SAML standard requires the entityId to be an absolute URI. Typically it should be the URL where the metadata 
    is presented. E.g. http://sp.example.com/Saml2/.

``entityFormat``
    The format used to represent the entityId. If omitted, it is assumed to be the default of ``urn:oasis:names:tc:SAML:2.0:nameid-format:entity``.

	The SAML standard requires the entityFormat to be an URN. 

``entityNameQualifier``
    The scope for the entityId. If omitted the entityId will be assumed in the global scope.

	The SAML standard requires the entityFormat to be an absolute URI.

``discoveryService`` (Optional)
    Specifies an idp discovery service to use if no idp is specified when calling sign in. Without 
    this attribute, the first idp known will be used if none is specified.

``modulePath`` (Optional)
     Indicates the base path of the Saml2 endpoints. Defaults to /Saml2 if not specified. This can usually be left as the 
     default, but if several instances of Saml2 are loaded into the same process they must each get a separate base path.

``authenticateRequestSigningBehavior`` (Optional)
    Sets the signing behavior for generated AuthnRequests. Three values are supported:

    * ``Never``: Saml2 will never sign any created AuthnRequests.
    * ``Always``: Saml2 will always sign all AuthnRequests.
    * ``IfIdpWantAuthnRequestsSigned`` (default if the attribute is missing): Saml2 will sign AuthnRequests if the idp is configured for it (through config or listed in idp metadata).

``validateCertificates`` (Optional)
    Normally certificates for the IDPs signing use is communicated through metadata and in case of a breach, the 
    metadata is updated with new data. If you want extra security, you can enable certificate validation (the 
    default value for this attribute is ``false``). Please note that the SAML metadata specification explicitly 
    places no requirements on certificate validation, so don't be surprised if an Idp certificate doesn't pass validation.

``publicOrigin`` (Optional)
    Indicates the base url of the Saml2 endpoints. It should be the root path of the application. E.g. The SignIn url is 
    built up as ``PublicOrigin + / + modulePath + /SignIn``. Defaults to Url of the current http request if not 
    specified. This can usually be left as the default, but if your internal address of the application is 
    different than the external address the generated URLs (such as ``AssertionConsumerServiceURL`` in the 
    ``saml2p:AuthnRequest``) then this will be incorrect. The use case for this is typically with load balancers 
    or reverse proxies. It can also be used if the application can be accessed by several external URLs to make sure 
    that the registered in metadata is used in communication with the Idp.

    If you need to set this value on a per-request basis, provide a ``GetPublicOrigin`` Notification function instead.

``outboundSignAlgorithm`` (Optional)
    By default Saml2 uses SHA256 signatures if running on .NET 4.6.2 or later or when you 
    have called ``GlobalEnableSha256XmlSignatures()``. Otherwise, it uses SHA1 signatures. Use this attribute to 
    set the default signing algorithm for any messages (including metadata) that Saml2 generates. Possible values:

    * ``SHA1`` (or http://www.w3.org/2000/09/xmldsig#rsa-sha1)
    * ``SHA256``
    * ``SHA384``
    * ``SHA512``

    The full url identifying the algorithm can also be provided. The algorithm can be overridden for each IdentityProvider 
    too.

``minIncomingSigningAlgorithm`` (Optional)
    The minimum strength required on signatures on incoming messages. Messages with a too weak signing algorithm will be 
    rejected.  By default Saml2 requires SHA256 signatures if running on .NET 4.6.2 or later or when you have 
    called ``GlobalEnableSha256XmlSignatures()``. Otherwise, it uses SHA1 signatures.
    
    Possible values:

    * ``SHA1`` (or http://www.w3.org/2000/09/xmldsig#rsa-sha1)
    * ``SHA256``
    * ``SHA384``
    * ``SHA512``
    
    The full url identifying the algorithm can also be provided.

Elements
--------
The following are the possible children elements of the ``<sustainsys.saml2>`` element.  Each are provided as a 
link below with full explanations of each. 

* :doc:`nameIdPolicy <name-id-policy>`
* :doc:`requestedAuthnContext <requested-authn-context>`
* :doc:`metadata <metadata>`
* :doc:`identityProviders <identity-providers>`
* :doc:`federations <federations>`
* :doc:`serviceCertificates <service-certificates>`
* :doc:`compatibility <compatibility>`