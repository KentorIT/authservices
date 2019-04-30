using Microsoft.IdentityModel.Tokens.Saml2;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Sustainsys.Saml2.Internal;
using System.Security.Cryptography.X509Certificates;
using Sustainsys.Saml2.Metadata;

namespace Sustainsys.Saml2.Saml2P
{
    /// <summary>
    /// Base class for saml requests, corresponds to section 3.2.1 in SAML Core specification.
    /// </summary>
    public abstract class Saml2RequestBase : ISaml2Message
    {
        private Saml2Id id = new Saml2Id("id" + Guid.NewGuid().ToString("N"));

        /// <summary>
        /// The id of the request.
        /// </summary>
        public Saml2Id Id
        {
            get
            {
                return id;
            }
            protected set
            {
                id = value;
            }
        }

        /// <summary>
        /// Version of the SAML request. Always returns "2.0"
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        public string Version
        {
            get
            {
                return "2.0";
            }
        }

        private readonly string issueInstant =
            DateTime.UtcNow.ToSaml2DateTimeString();

        /// <summary>
        /// The instant that the request was issued (well actually, created).
        /// </summary>
        public string IssueInstant
        {
            get
            {
                return issueInstant;
            }
        }

        /// <summary>
        /// SAML message name for requests - hard coded to SAMLRequest.
        /// </summary>
        public string MessageName
        {
            get
            {
                return "SAMLRequest";
            }
        }

        /// <summary>
        /// The destination of the request.
        /// </summary>
        public Uri DestinationUrl { get; set; }

        /// <summary>
        /// The issuer of the request.
        /// </summary>
        public EntityId Issuer { get; set; }

        /// <summary>
        /// The issuer format of the request.
        /// </summary>
        public Uri IssuerFormat { get; set; }

        /// <summary>
        /// The issuer name qualifier of the request.
        /// </summary>
        public Uri IssuerNameQualifier { get; set; }

        /// <summary>
        /// The SAML2 request name
        /// </summary>
        protected abstract string LocalName { get; }

        /// <summary>
        /// Creates XNodes for the fields of the Saml2RequestBase class. These
        /// nodes should be added when creating XML out of derived classes.
        /// </summary>
        /// <returns></returns>
        protected IEnumerable<XObject> ToXNodes()
        {
            yield return new XAttribute(XNamespace.Xmlns + "saml2p", Saml2Namespaces.Saml2PName);
            yield return new XAttribute(XNamespace.Xmlns + "saml2", Saml2Namespaces.Saml2Name);
            yield return new XAttribute("ID", Id.Value);
            yield return new XAttribute("Version", Version);
            yield return new XAttribute("IssueInstant", IssueInstant);

            if (DestinationUrl != null)
            {
                yield return new XAttribute("Destination", DestinationUrl.OriginalString);
            }

            if (Issuer != null && !string.IsNullOrEmpty(Issuer.Id))
            {
                yield return new XElement(Saml2Namespaces.Saml2 + "Issuer",
                    IssuerFormat != null ? new XAttribute("Format", IssuerFormat): null,
                    IssuerNameQualifier != null ? new XAttribute("NameQualifier", IssuerNameQualifier) : null,
                    Issuer.Id);
            }
        }

        /// <summary>
        /// Reads the request properties present in Saml2RequestBase
        /// Also validates basic properties of the request
        /// </summary>
        /// <param name="xml">The xml document to parse</param>
        protected void ReadBaseProperties(XmlElement xml)
        {
            if (xml == null)
            {
                throw new ArgumentNullException(nameof(xml));
            }
            ValidateCorrectDocument(xml);
            Id = new Saml2Id(xml.Attributes["ID"].Value);

            var destination = xml.Attributes["Destination"];
            if(destination != null)
            {
                DestinationUrl = new Uri(destination.Value);
            }

            var issuerNode = xml["Issuer", Saml2Namespaces.Saml2Name];
            if(issuerNode != null)
            {
                Issuer = new EntityId(issuerNode.InnerXml);

                var issuerFormatAttribute = issuerNode.Attributes["Format"];
                if (issuerFormatAttribute != null)
                    IssuerFormat = new Uri(issuerFormatAttribute.Value);

                var issuerNameQualifierAttribute = issuerNode.Attributes["NameQualifier"];
                if (issuerNameQualifierAttribute != null)
                    IssuerNameQualifier = new Uri(issuerNameQualifierAttribute.Value);
            }
        }

        private void ValidateCorrectDocument(XmlElement xml)
        {
            if (xml.LocalName != LocalName
               || xml.NamespaceURI != Saml2Namespaces.Saml2P)
            {
                throw new XmlException("Expected a SAML2 authentication request document");
            }

            if (xml.Attributes["Version"].Value != "2.0")
            {
                throw new XmlException("Wrong or unsupported SAML2 version");
            }
        }

        /// <summary>
        /// Serializes the message into wellformed Xml.
        /// </summary>
        /// <returns>string containing the Xml data.</returns>
        public abstract string ToXml();

        /// <summary>
        /// RelayState attached to the message.
        /// </summary>
        public string RelayState { get; protected set; }

        /// <summary>
        /// Certificate used to sign the message with during binding, according
        /// to the signature processing rules of each binding.
        /// </summary>
        public X509Certificate2 SigningCertificate { get; set; }
        /// <summary>
        /// The signing algorithm to use when signing the message during binding, 
        /// according to the signature processing rules of each binding.
        /// </summary>
        /// <value>The signing algorithm.</value>
        public string SigningAlgorithm { get; set; }
    }
}
