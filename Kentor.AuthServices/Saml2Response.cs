﻿using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Kentor.AuthServices.Configuration;

namespace Kentor.AuthServices
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
            var x = new XmlDocument();
            x.PreserveWhitespace = true;
            x.LoadXml(xml);

            if (x.DocumentElement.LocalName != "Response"
                || x.DocumentElement.NamespaceURI != Saml2Namespaces.Saml2P)
            {
                throw new XmlException("Expected a SAML2 assertion document");
            }

            if (x.DocumentElement.Attributes["Version"].Value != "2.0")
            {
                throw new XmlException("Wrong or unsupported SAML2 version");
            }

            return new Saml2Response(x);
        }

        private Saml2Response(XmlDocument xml)
        {
            xmlDocument = xml;

            id = new Saml2Id(xml.DocumentElement.Attributes["ID"].Value);

            var parsedInResponseTo = xml.DocumentElement.Attributes["InResponseTo"].GetValueIfNotNull();
            if (parsedInResponseTo != null)
            {
                inResponseTo = new Saml2Id(parsedInResponseTo);
            }

            issueInstant = DateTime.Parse(xml.DocumentElement.Attributes["IssueInstant"].Value,
                CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal);

            var statusString = xml.DocumentElement["Status", Saml2Namespaces.Saml2PName]
                ["StatusCode", Saml2Namespaces.Saml2PName].Attributes["Value"].Value;

            status = StatusCodeHelper.FromString(statusString);

            issuer = xmlDocument.DocumentElement["Issuer", Saml2Namespaces.Saml2Name].GetTrimmedTextIfNotNull();

            var destinationUriString = xmlDocument.DocumentElement.Attributes["Destination"].GetValueIfNotNull();

            if (destinationUriString != null)
            {
                destinationUri = new Uri(destinationUriString);
            }
        }

        /// <summary>
        /// Create a response with the supplied data.
        /// </summary>
        /// <param name="issuer">Issuer of the response.</param>
        /// <param name="issuerCertificate">The certificate to use when signing
        /// this response in XML form.</param>
        /// <param name="destinationUri">The destination Uri for the message</param>
        /// <param name="claimsIdentities">Claims identities to be included in the 
        /// response. Each identity is translated into a separate assertion.</param>
        public Saml2Response(string issuer, X509Certificate2 issuerCertificate,
            Uri destinationUri, params ClaimsIdentity[] claimsIdentities)
        {
            this.issuer = issuer;
            this.claimsIdentities = claimsIdentities;
            this.issuerCertificate = issuerCertificate;
            this.destinationUri = destinationUri;
            id = new Saml2Id("id" + Guid.NewGuid().ToString("N"));
            status = Saml2StatusCode.Success;
        }

        private readonly X509Certificate2 issuerCertificate;

        private XmlDocument xmlDocument;

        /// <summary>
        /// The response as an xml docuemnt. Either the original xml, or xml that is
        /// generated from supplied data.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1059:MembersShouldNotExposeCertainConcreteTypes", MessageId = "System.Xml.XmlNode")]
        public XmlDocument XmlDocument
        {
            get
            {
                if (xmlDocument == null)
                {
                    CreateXmlDocument();
                }

                return xmlDocument;
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
            return XmlDocument.OuterXml;
        }

        private void CreateXmlDocument()
        {
            var xml = new XmlDocument();
            xml.AppendChild(xml.CreateXmlDeclaration("1.0", null, null));

            var responseElement = xml.CreateElement("saml2p", "Response", Saml2Namespaces.Saml2PName);

            if (DestinationUri != null)
            {
                responseElement.SetAttributeNode("Destination", "").Value = DestinationUri.ToString();
            }

            responseElement.SetAttributeNode("ID", "").Value = id.Value;
            responseElement.SetAttributeNode("Version", "").Value = "2.0";
            responseElement.SetAttributeNode("IssueInstant", "").Value =
                DateTime.UtcNow.ToSaml2DateTimeString();
            xml.AppendChild(responseElement);

            var issuerElement = xml.CreateElement("saml2", "Issuer", Saml2Namespaces.Saml2Name);
            issuerElement.InnerText = issuer;
            responseElement.AppendChild(issuerElement);

            var statusElement = xml.CreateElement("saml2p", "Status", Saml2Namespaces.Saml2PName);
            var statusCodeElement = xml.CreateElement("saml2p", "StatusCode", Saml2Namespaces.Saml2PName);
            statusCodeElement.SetAttributeNode("Value", "").Value = StatusCodeHelper.FromCode(Status);
            statusElement.AppendChild(statusCodeElement);
            responseElement.AppendChild(statusElement);

            foreach (var ci in claimsIdentities)
            {
                responseElement.AppendChild(xml.ReadNode(
                    ci.ToSaml2Assertion(issuer).ToXElement().CreateReader()));
            }

            xmlDocument = xml;

            xml.Sign(issuerCertificate);
        }

        readonly Saml2Id id;

        /// <summary>
        /// Id of the response message.
        /// </summary>
        public Saml2Id Id { get { return id; } }

        readonly Saml2Id inResponseTo;

        /// <summary>
        /// InResponseTo id.
        /// </summary>
        public Saml2Id InResponseTo { get { return inResponseTo; } }

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

        readonly string issuer;

        /// <summary>
        /// Issuer (= sender) of the response.
        /// </summary>
        public string Issuer
        {
            get
            {
                return issuer;
            }
        }

        readonly Uri destinationUri;

        /// <summary>
        /// The destination of the response message.
        /// </summary>
        public Uri DestinationUri
        {
            get
            {
                return destinationUri;
            }
        }

        bool valid = false, validated = false;

        /// <summary>Gets all assertion element nodes from this response message.</summary>
        /// <value>All assertion element nodes.</value>
        private IEnumerable<XmlElement> AllAssertionElementNodes
        {
            get
            {
                if (allAssertionElementNodes == null)
                {
                    allAssertionElementNodes =
                        XmlDocument.DocumentElement.ChildNodes.Cast<XmlNode>()
                        .Where(node => node.NodeType == XmlNodeType.Element).Cast<XmlElement>()
                        .Where(xe => xe.LocalName == "Assertion" && xe.NamespaceURI == Saml2Namespaces.Saml2Name);
                }

                return allAssertionElementNodes;
            }
        }

        /// <summary>
        /// Validates InResponseTo and the signature of the response. Note that the status code of the
        /// message can still be an error code, although the message itself is valid.
        /// </summary>
        /// <param name="idpCertificate">Idp certificate that should have signed the reponse</param>
        /// <returns>Is the response signed by the Idp and fulfills other formal requirements?</returns>
        public bool Validate(X509Certificate2 idpCertificate)
        {
            if (!validated)
            {
                valid = ValidateInResponseTo() && ValidateSignature(idpCertificate);

                validated = true;
            }
            return valid;
        }

        private bool ValidateInResponseTo()
        {
            if (InResponseTo == null &&
                KentorAuthServicesSection.Current.IdentityProviders
                .Single(idpConfig => idpConfig.Issuer == this.Issuer).AllowUnsolicitedAuthnResponse)
            {
                return true;
            }
            else
            {
                string sentToIdp;
                bool knownInResponseToId = PendingAuthnRequests.TryRemove(InResponseTo, out sentToIdp);
                if (!knownInResponseToId)
                {
                    return false;
                }
                if (sentToIdp != Issuer)
                {
                    return false;
                }
                return true;
            }
        }

        private bool ValidateSignature(X509Certificate2 idpCertificate)
        {
            // If the response message is signed, we check just this signature because the whole content has to be correct then
            var responseSignature = xmlDocument.DocumentElement["Signature", SignedXml.XmlDsigNamespaceUrl];
            if (responseSignature != null)
            {
                return CheckSignature(XmlDocument.DocumentElement, idpCertificate);
            }
            else
            {
                // If the response message is not signed, all assersions have to be signed correctly
                foreach (var assertionNode in AllAssertionElementNodes)
                {
                    if (!CheckSignature(assertionNode, idpCertificate))
                    {
                        return false;
                    }
                }
                return true;
            }
        }

        private static readonly string[] allowedTransforms = new string[]
        {
            SignedXml.XmlDsigEnvelopedSignatureTransformUrl,
            SignedXml.XmlDsigExcC14NTransformUrl,
            SignedXml.XmlDsigExcC14NWithCommentsTransformUrl
        };

        /// <summary>Checks the signature.</summary>
        /// <param name="signedRootElement">The signed root element.</param>
        /// <param name="idpCertificate">The idp certificate.</param>
        /// <returns><c>true</c> if the whole signature was successful; otherwise <c>false</c></returns>
        private static bool CheckSignature(XmlElement signedRootElement, X509Certificate2 idpCertificate)
        {
            var xmlDocument = new XmlDocument { PreserveWhitespace = true };
            xmlDocument.LoadXml(signedRootElement.OuterXml);

            var signature = xmlDocument.DocumentElement["Signature", SignedXml.XmlDsigNamespaceUrl];
            if (signature == null)
            {
                return false;
            }

            var signedXml = new SignedXml(xmlDocument);
            signedXml.LoadXml(signature);

            var signedRootElementId = "#" + signedRootElement.GetAttribute("ID");

            var reference = signedXml.SignedInfo.References.Cast<Reference>().FirstOrDefault();
            
            if (signedXml.SignedInfo.References.Count != 1 || reference.Uri != signedRootElementId)
            {
                return false;
            }

            foreach (Transform transform in reference.TransformChain)
            {
                if (!allowedTransforms.Contains(transform.Algorithm))
                {
                    return false;
                }
            }

            return signedXml.CheckSignature(idpCertificate, true);
        }

        private void ThrowOnNotValid()
        {
            if (!validated)
            {
                throw new InvalidOperationException("The Saml2Response must be validated first.");
            }
            if (!valid)
            {
                throw new InvalidOperationException("The Saml2Response didn't pass validation");
            }
            if (status != Saml2StatusCode.Success)
            {
                throw new InvalidOperationException("The Saml2Response must have status success to extract claims.");
            }
        }

        private IEnumerable<ClaimsIdentity> claimsIdentities;
        private Exception createClaimsException;

        /// <summary>
        /// Extract claims from the assertions contained in the response.
        /// </summary>
        /// <returns>ClaimsIdentities</returns>
        // Method might throw expections so make it a method and not a property.
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1024:UsePropertiesWhereAppropriate")]
        public IEnumerable<ClaimsIdentity> GetClaims()
        {
            if (createClaimsException != null)
            {
                throw createClaimsException;
            }

            if (claimsIdentities == null)
            {
                try
                {
                    claimsIdentities = CreateClaims().ToList();
                }
                catch (Exception ex)
                {
                    createClaimsException = ex;
                    throw;
                }
            }

            return claimsIdentities;
        }

        private IEnumerable<Saml2SecurityToken> saml2SecurityTokens;

        /// <summary>Gets the saml2 security tokens converted from the assertions in the response.</summary>
        /// <value>The saml2 security tokens.</value>
        public virtual IEnumerable<Saml2SecurityToken> Saml2SecurityTokens
        {
            get
            {
                return saml2SecurityTokens ?? (saml2SecurityTokens = ConvertAssertionsToValidatedSaml2SecurityTokens());
            }
        }

        /// <summary>Converts the assertions to validated saml2 security tokens.</summary>
        /// <returns>A enumerable of Saml2SecurityToken</returns>
        protected virtual IEnumerable<Saml2SecurityToken> ConvertAssertionsToValidatedSaml2SecurityTokens()
        {
            ThrowOnNotValid();

            var tokens = new List<Saml2SecurityToken>();
            foreach (XmlElement assertionNode in AllAssertionElementNodes)
            {
                using (var reader = new XmlNodeReader(assertionNode))
                {
                    var handler = MorePublicSaml2SecurityTokenHandler.DefaultInstance;

                    var token = (Saml2SecurityToken)handler.ReadToken(reader);

                    // Replayed token detection has to be activated by configuration.
                    // The configuration value is handled inside DetectReplayedToken
                    handler.DetectReplayedToken(token);

                    // The saml assertion spec does not require any conditions -> Check for null
                    var validateAudience = token.Assertion.Conditions != null && token.Assertion.Conditions.AudienceRestrictions.Count > 0;

                    handler.ValidateConditions(token.Assertion.Conditions, validateAudience);

                    tokens.Add(token);
                }
            }

            return tokens;
        }

        private IEnumerable<ClaimsIdentity> CreateClaims()
        {
            foreach (var token in Saml2SecurityTokens)
            {
                var handler = MorePublicSaml2SecurityTokenHandler.DefaultInstance;
                yield return handler.CreateClaims(token);
            }
        }
    }
}
