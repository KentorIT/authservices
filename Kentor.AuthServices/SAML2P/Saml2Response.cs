using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Kentor.AuthServices.Configuration;
using System.IdentityModel.Metadata;
using System.Security.Cryptography;
using System.IdentityModel.Services;
using Kentor.AuthServices.Internal;
using Kentor.AuthServices.Exceptions;
using System.Diagnostics.CodeAnalysis;

namespace Kentor.AuthServices.Saml2P
{
    /// <summary>
    /// Represents a SAML2 response according to 3.3.3. The class is immutable (to an
    /// external observer. Internal state is lazy initiated).
    /// </summary>
    public class Saml2Response : ISaml2Message
    {
        /// <summary>Holds all assertion element nodes</summary>
        private IEnumerable<XmlElement> allAssertionElementNodes;

        /// <summary>
        /// Read the supplied Xml and parse it into a response.
        /// </summary>
        /// <param name="xml">xml data.</param>
        /// <returns>Saml2Response</returns>
        /// <exception cref="XmlException">On xml errors or unexpected xml structure.</exception>
        public static Saml2Response Read(string xml)
        {
            return Read(xml, null);
        }

        /// <summary>
        /// Read the supplied Xml and parse it into a response.
        /// </summary>
        /// <param name="xml">xml data.</param>
        /// <param name="expectedInResponseTo">The expected value of the
        /// InReplyTo parameter in the message.</param>
        /// <returns>Saml2Response</returns>
        /// <exception cref="XmlException">On xml errors or unexpected xml structure.</exception>
        public static Saml2Response Read(string xml, Saml2Id expectedInResponseTo)
        {
            var x = XmlHelpers.XmlDocumentFromString(xml);

            return new Saml2Response(x.DocumentElement, expectedInResponseTo);
        }

        /// <summary>
        /// Ctor
        /// </summary>
        /// <param name="xml">Root xml element.</param>
        /// <param name="expectedInResponseTo">The expected value of the
        /// InReplyTo parameter in the message.</param>
        public Saml2Response(XmlElement xml, Saml2Id expectedInResponseTo)
        {
            if (xml == null)
            {
                throw new ArgumentNullException(nameof(xml));
            }

            if (xml.LocalName != "Response"
                || xml.NamespaceURI != Saml2Namespaces.Saml2P)
            {
                throw new XmlException("Expected a SAML2 assertion document");
            }

            if (xml.Attributes["Version"].Value != "2.0")
            {
                throw new XmlException("Wrong or unsupported SAML2 version");
            }

            xmlElement = xml;

            id = new Saml2Id(xml.Attributes["ID"].Value);

            ReadAndValidateInResponseTo(xml, expectedInResponseTo);

            issueInstant = DateTime.Parse(xml.Attributes["IssueInstant"].Value,
                CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal);

            var statusString = xml["Status", Saml2Namespaces.Saml2PName]
                ["StatusCode", Saml2Namespaces.Saml2PName].Attributes["Value"].Value;

            status = StatusCodeHelper.FromString(statusString);

            statusMessage = xml["Status", Saml2Namespaces.Saml2PName]
                ["StatusMessage", Saml2Namespaces.Saml2PName].GetTrimmedTextIfNotNull();
            if (xml["Status", Saml2Namespaces.Saml2PName]["StatusCode", Saml2Namespaces.Saml2PName]["StatusCode", Saml2Namespaces.Saml2PName] != null)
            {
                secondLevelStatus = xml["Status", Saml2Namespaces.Saml2PName]["StatusCode", Saml2Namespaces.Saml2PName]["StatusCode", Saml2Namespaces.Saml2PName].Attributes["Value"].Value;
            }

            Issuer = new EntityId(xmlElement["Issuer", Saml2Namespaces.Saml2Name].GetTrimmedTextIfNotNull());

            var destinationUrlString = xmlElement.Attributes["Destination"].GetValueIfNotNull();

            if (destinationUrlString != null)
            {
                Uri parsedDestination;
                if (!Uri.TryCreate(destinationUrlString, UriKind.Absolute, out parsedDestination))
                {
                    throw new BadFormatSamlResponseException("Destination value was not a valid Uri");
                }
                DestinationUrl = parsedDestination;
            }
        }

        [SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "InResponseTo")]
        [SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "RelayState")]
        private void ReadAndValidateInResponseTo(XmlElement xml, Saml2Id expectedInResponseTo)
        {
            var parsedInResponseTo = xml.Attributes["InResponseTo"].GetValueIfNotNull();
            if (parsedInResponseTo != null)
            {
                InResponseTo = new Saml2Id(parsedInResponseTo);
                if (expectedInResponseTo == null)
                {
                    throw new UnexpectedInResponseToException(
                        string.Format(CultureInfo.InvariantCulture,
                        "Received message contains unexpected InResponseTo \"{0}\". No cookie preserving state " +
                        "from the request was found so the message was not expected to have an InResponseTo attribute. " +
                        "This error typically occurs if the cookie set when doing SP-initiated sign on have been lost.",
                        InResponseTo));
                }
                if (!expectedInResponseTo.Equals(InResponseTo))
                {
                    throw new Saml2ResponseFailedValidationException(
                        string.Format(CultureInfo.InvariantCulture,
                        "InResponseTo Id \"{0}\" in received response does not match Id \"{1}\" of the sent request.",
                        InResponseTo, expectedInResponseTo));
                }
            }
            else
            {
                if (expectedInResponseTo != null)
                {
                    throw new Saml2ResponseFailedValidationException(
                        string.Format(CultureInfo.InvariantCulture,
                        "Expected message to contain InResponseTo \"{0}\", but found none.",
                        expectedInResponseTo));
                }
            }
        }

        /// <summary>
        /// Create a response with the supplied data.
        /// </summary>
        /// <param name="issuer">Issuer of the response.</param>
        /// <param name="signingCertificate">The certificate to use when signing
        /// this response in XML form.</param>
        /// <param name="destinationUrl">The destination Uri for the message</param>
        /// <param name="inResponseTo">In response to id</param>
        /// <param name="claimsIdentities">Claims identities to be included in the 
        /// response. Each identity is translated into a separate assertion.</param>
        public Saml2Response(
            EntityId issuer,
            X509Certificate2 signingCertificate,
            Uri destinationUrl,
            Saml2Id inResponseTo,
            params ClaimsIdentity[] claimsIdentities)
            : this(issuer, signingCertificate, destinationUrl, inResponseTo, null, claimsIdentities)
        { }

        /// <summary>
        /// Create a response with the supplied data.
        /// </summary>
        /// <param name="issuer">Issuer of the response.</param>
        /// <param name="signingCertificate">The certificate to use when signing
        /// this response in XML form.</param>
        /// <param name="destinationUrl">The destination Uri for the message</param>
        /// <param name="inResponseTo">In response to id</param>
        /// <param name="relayState">RelayState associated with the message.</param>
        /// <param name="claimsIdentities">Claims identities to be included in the 
        /// response. Each identity is translated into a separate assertion.</param>
        public Saml2Response(
            EntityId issuer,
            X509Certificate2 signingCertificate,
            Uri destinationUrl,
            Saml2Id inResponseTo,
            string relayState,
            params ClaimsIdentity[] claimsIdentities)
            : this(issuer, signingCertificate, destinationUrl, inResponseTo, relayState, null, claimsIdentities)
        { }

        /// <summary>
        /// Create a response with the supplied data.
        /// </summary>
        /// <param name="issuer">Issuer of the response.</param>
        /// <param name="issuerCertificate">The certificate to use when signing
        /// this response in XML form.</param>
        /// <param name="destinationUrl">The destination Uri for the message</param>
        /// <param name="inResponseTo">In response to id</param>
        /// <param name="relayState">RelayState associated with the message.</param>
        /// <param name="claimsIdentities">Claims identities to be included in the 
        /// <param name="audience">Audience of the response, set as AudienceRestriction</param>
        /// response. Each identity is translated into a separate assertion.</param>
        public Saml2Response(
            EntityId issuer,
            X509Certificate2 issuerCertificate,
            Uri destinationUrl,
            Saml2Id inResponseTo,
            string relayState,
            Uri audience,
            params ClaimsIdentity[] claimsIdentities )
            : this( issuer, issuerCertificate, destinationUrl, inResponseTo, relayState, audience, 
                null, claimsIdentities )
        { }

        /// <summary>
        /// Create a response with the supplied data.
        /// </summary>
        /// <param name="issuer">Issuer of the response.</param>
        /// <param name="issuerCertificate">The certificate to use when signing
        /// this response in XML form.</param>
        /// <param name="destinationUrl">The destination Uri for the message</param>
        /// <param name="inResponseTo">In response to id</param>
        /// <param name="relayState">RelayState associated with the message.</param>
        /// <param name="sessionNotOnOrAfter">The time instant at which the session between the principal 
        /// identified by the subject and the SAML authority issuing this statement
        /// must be considered ended.</param>
        /// <param name="claimsIdentities">Claims identities to be included in the 
        /// <param name="audience">Audience of the response, set as AudienceRestriction</param>
        /// response. Each identity is translated into a separate assertion.</param>
        public Saml2Response(
            EntityId issuer,
            X509Certificate2 issuerCertificate,
            Uri destinationUrl,
            Saml2Id inResponseTo,
            string relayState,
            Uri audience,
            DateTime? sessionNotOnOrAfter,
            params ClaimsIdentity[] claimsIdentities)
        {
            Issuer = issuer;
            this.claimsIdentities = claimsIdentities;
            SigningCertificate = issuerCertificate;
            SigningAlgorithm = XmlHelpers.GetDefaultSigningAlgorithmName();
            DestinationUrl = destinationUrl;
            RelayState = relayState;
            InResponseTo = inResponseTo;
            id = new Saml2Id("id" + Guid.NewGuid().ToString("N"));
            status = Saml2StatusCode.Success;
            this.audience = audience;
            this.sessionNotOnOrAfter = sessionNotOnOrAfter;
        }

        /// <summary>
        /// Certificate used to sign the message with during binding, according
        /// to the signature processing rules of each binding.
        /// </summary>
        [ExcludeFromCodeCoverage]
        public X509Certificate2 SigningCertificate { get; }

        /// <summary>
        /// The signing algorithm to use when signing the message during binding, 
        /// according to the signature processing rules of each binding.
        /// </summary>
        /// <value>The signing algorithm.</value>
        [ExcludeFromCodeCoverage]
        public string SigningAlgorithm { get; set; }

        private XmlElement xmlElement;

        /// <summary>
        /// The response as an xml element. Either the original xml, or xml that is
        /// generated from supplied data.
        /// </summary>
        public XmlElement XmlElement
        {
            get
            {
                if (xmlElement == null)
                {
                    CreateXmlElement();
                }

                return xmlElement;
            }
        }

        /// <summary>
        /// SAML Message name for responses, hard coded to SAMLResponse.
        /// </summary>
        public string MessageName
        {
            get
            {
                return "SAMLResponse";
            }
        }

        /// <summary>
        /// string representation of the Saml2Response serialized to xml.
        /// </summary>
        /// <returns>string containing xml.</returns>
        public string ToXml()
        {
            return XmlElement.OuterXml;
        }

        private void CreateXmlElement()
        {
            var xml = XmlHelpers.CreateSafeXmlDocument();

            var responseElement = xml.CreateElement("saml2p", "Response", Saml2Namespaces.Saml2PName);

            if (DestinationUrl != null)
            {
                responseElement.SetAttributeNode("Destination", "").Value = DestinationUrl.ToString();
            }

            responseElement.SetAttributeNode("ID", "").Value = id.Value;
            responseElement.SetAttributeNode("Version", "").Value = "2.0";
            responseElement.SetAttributeNode("IssueInstant", "").Value =
                DateTime.UtcNow.ToSaml2DateTimeString();
            if (InResponseTo != null)
            {
                responseElement.SetAttributeNode("InResponseTo", "").Value = InResponseTo.Value;
            }
            xml.AppendChild(responseElement);

            var issuerElement = xml.CreateElement("saml2", "Issuer", Saml2Namespaces.Saml2Name);
            issuerElement.InnerText = Issuer.Id;
            responseElement.AppendChild(issuerElement);

            var statusElement = xml.CreateElement("saml2p", "Status", Saml2Namespaces.Saml2PName);
            var statusCodeElement = xml.CreateElement("saml2p", "StatusCode", Saml2Namespaces.Saml2PName);
            statusCodeElement.SetAttributeNode("Value", "").Value = StatusCodeHelper.FromCode(Status);
            statusElement.AppendChild(statusCodeElement);
            responseElement.AppendChild(statusElement);

            foreach (var ci in claimsIdentities)
            {
                responseElement.AppendChild(xml.ReadNode(
                    ci.ToSaml2Assertion(Issuer, audience, InResponseTo, DestinationUrl,SessionNotOnOrAfter).ToXElement().CreateReader()));
            }

            xmlElement = xml.DocumentElement;
        }

        readonly Saml2Id id;

        /// <summary>
        /// Id of the response message.
        /// </summary>
        public Saml2Id Id { get { return id; } }

        /// <summary>
        /// InResponseTo id.
        /// </summary>
        public Saml2Id InResponseTo { get; private set; }

        readonly DateTime issueInstant;

        /// <summary>
        /// Issue instant of the response message.
        /// </summary>
        public DateTime IssueInstant { get { return issueInstant; } }

        readonly Saml2StatusCode status;

        /// <summary>
        /// Status code of the message according to the SAML2 spec section 3.2.2.2
        /// </summary>
        public Saml2StatusCode Status { get { return status; } }

        readonly string statusMessage;

        /// <summary>
        /// StatusMessage of the message according to the SAML2 spec section 3.2.2.1
        /// </summary>
        public string StatusMessage { get { return statusMessage; } }

        readonly string secondLevelStatus;
        /// <summary>
        /// Optional status which MAY give additional information about the cause of the problem (according to the SAML2 spec section 3.2.2.2))))))))). 
        /// Because it may change in future specifications let's not make enum out of it yet.
        /// </summary>
        public string SecondLevelStatus { get { return secondLevelStatus; } }

        /// <summary>
        /// Issuer (= sender) of the response.
        /// </summary>
        public EntityId Issuer { get; }

        /// <summary>
        /// The destination of the response message.
        /// </summary>
        public Uri DestinationUrl { get; }

        /// <summary>Gets all assertion element nodes from this response message.</summary>
        /// <value>All assertion element nodes.</value>
        private IEnumerable<XmlElement> GetAllAssertionElementNodes(IOptions options)
        {
            return allAssertionElementNodes ?? (allAssertionElementNodes = retrieveAssertionElements(options));
        }

        private IEnumerable<XmlElement> retrieveAssertionElements(IOptions options)
        {
            var assertions = new List<XmlElement>();

            assertions.AddRange(XmlElement.ChildNodes.Cast<XmlNode>()
                .Where(node => node.NodeType == XmlNodeType.Element).Cast<XmlElement>()
                .Where(xe => xe.LocalName == "Assertion" && xe.NamespaceURI == Saml2Namespaces.Saml2Name));

            var encryptedAssertions = XmlElement.ChildNodes.Cast<XmlNode>()
                .Where(node => node.NodeType == XmlNodeType.Element).Cast<XmlElement>()
                .Where(xe => xe.LocalName == "EncryptedAssertion" && xe.NamespaceURI == Saml2Namespaces.Saml2Name);

            if (encryptedAssertions.Count() > 0)
            {
                options.SPOptions.Logger.WriteVerbose("Found encrypted assertions, decrypting...");

                var decryptionCertificates = GetCertificatesValidForDecryption(options);

                bool decrypted = false;
                foreach (var serviceCertificate in decryptionCertificates)
                {
                    try
                    {
                        assertions.AddRange(encryptedAssertions.Decrypt(serviceCertificate.PrivateKey)
                                .Select(xe => (XmlElement)xe.GetElementsByTagName("Assertion", Saml2Namespaces.Saml2Name)[0]));
                        decrypted = true;
                        break;
                    }
                    catch (CryptographicException)
                    {
                        // we cannot depend on Idp's sending KeyInfo, so this is the only 
                        // reliable way to know we've got the wrong cert
                    }
                }
                if (!decrypted)
                {
                    throw new Saml2ResponseFailedValidationException("Encrypted Assertion(s) could not be decrypted using the configured Service Certificate(s).");
                }
            }

            return assertions;
        }

        private static IEnumerable<X509Certificate2> GetCertificatesValidForDecryption(IOptions options)
        {
            var decryptionCertificates = options.SPOptions.DecryptionServiceCertificates;

            if (decryptionCertificates.Count == 0)
            {
                throw new Saml2ResponseFailedValidationException("Encrypted Assertions encountered but Service Certificate was not provided.");
            }

            return decryptionCertificates;
        }

        private void Validate(IOptions options)
        {
            CheckIfUnsolicitedIsAllowed(options);
            ValidateSignature(options);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "RelayState")]

        private void CheckIfUnsolicitedIsAllowed(IOptions options)
        {
            if (InResponseTo == null)
            {
                var idp = options.IdentityProviders[Issuer];
                if (idp.AllowUnsolicitedAuthnResponse)
                {
                    options.SPOptions.Logger.WriteVerbose("Received unsolicited Saml Response " + Id 
                        + " which is allowed for idp " + idp.EntityId.Id);
                    return;
                }
                string msg = string.Format(CultureInfo.InvariantCulture,
                    "Unsolicited responses are not allowed for idp \"{0}\".", Issuer.Id);
                throw new Saml2ResponseFailedValidationException(msg);
            }
        }

        private void ValidateSignature(IOptions options)
        {
            var idpKeys = options.IdentityProviders[Issuer].SigningKeys;

            var minAlgorithm = options.SPOptions.MinIncomingSigningAlgorithm;

            if(!xmlElement.IsSignedByAny(idpKeys, options.SPOptions.ValidateCertificates, minAlgorithm)
                && GetAllAssertionElementNodes(options)
                .Any(a => !a.IsSignedByAny(idpKeys, options.SPOptions.ValidateCertificates, minAlgorithm)))
            {
                throw new Saml2ResponseFailedValidationException("The SAML Response is not signed and contains unsigned Assertions. Response cannot be trusted.");
            }
            options.SPOptions.Logger.WriteVerbose("Signature validation passed for Saml Response " + Id);
        }

        private Uri audience;

        private IEnumerable<ClaimsIdentity> claimsIdentities;
        private Exception createClaimsException;

        /// <summary>
        /// Extract claims from the assertions contained in the response.
        /// </summary>
        /// <param name="options">Service provider settings used when processing the response into claims.</param>
        /// <returns>ClaimsIdentities</returns>
        // Method might throw expections so make it a method and not a property.
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1024:UsePropertiesWhereAppropriate")]
        public IEnumerable<ClaimsIdentity> GetClaims(IOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }
            if (createClaimsException != null)
            {
                throw createClaimsException;
            }

            if (claimsIdentities == null)
            {
                try
                {
                    claimsIdentities = CreateClaims(options).ToList();
                }
                catch (Exception ex)
                {
                    createClaimsException = ex;
                    throw;
                }
            }

            return claimsIdentities;
        }

        private IEnumerable<ClaimsIdentity> CreateClaims(IOptions options)
        {
            Validate(options);

            if (status != Saml2StatusCode.Success)
            {
                throw new UnsuccessfulSamlOperationException(
                    "The Saml2Response must have status success to extract claims.",
                    status, statusMessage, secondLevelStatus);
            }

            foreach (XmlElement assertionNode in GetAllAssertionElementNodes(options))
            {
                using (var reader = new FilteringXmlNodeReader(SignedXml.XmlDsigNamespaceUrl, "Signature", assertionNode))
                {
                    var handler = options.SPOptions.Saml2PSecurityTokenHandler;

                    var token = (Saml2SecurityToken)handler.ReadToken(reader);
                    options.SPOptions.Logger.WriteVerbose("Extracted SAML assertion " + token.Id);

                    handler.DetectReplayedToken(token);

                    var validateAudience = options.SPOptions
                        .Saml2PSecurityTokenHandler
                        .SamlSecurityTokenRequirement
                        .ShouldEnforceAudienceRestriction(options.SPOptions
                        .SystemIdentityModelIdentityConfiguration
                        .AudienceRestriction.AudienceMode, token);

                    handler.ValidateConditions(token.Assertion.Conditions, validateAudience);

                    options.SPOptions.Logger.WriteVerbose("Validated conditions for SAML2 Response " + Id);

                    sessionNotOnOrAfter = DateTimeHelper.EarliestTime(sessionNotOnOrAfter,
                    token.Assertion.Statements.OfType<Saml2AuthenticationStatement>()
                        .SingleOrDefault()?.SessionNotOnOrAfter);

                    yield return handler.CreateClaims(token);
                }
            }
        }
        
        /// <summary>
        /// RelayState attached to the message.
        /// </summary>
        public string RelayState { get; } = null;

        private DateTime? sessionNotOnOrAfter;

        /// <summary>
        /// Session termination time for a session generated from this
        /// response.
        /// </summary>
        [SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "GetClaims")]
        [SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "SessionNotOnOrAfter")]
        public DateTime? SessionNotOnOrAfter
        {
            get
            {
                if(claimsIdentities == null)
                {
                    // This is not a good design, but will have to do for now.
                    // The entire Saml2Response class needs some refactoring
                    // love - probably by extracting more stuff to the 
                    // Saml2PSecurityTokenHandler.
                    throw new InvalidOperationException("Accessing SessionNotOnOrAfter requires GetClaims to have been called first.");
                }
                return sessionNotOnOrAfter;
            }
        }

    }
}
