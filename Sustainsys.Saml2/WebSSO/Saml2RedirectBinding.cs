using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.Exceptions;
using Sustainsys.Saml2.Internal;
using Sustainsys.Saml2.Metadata;
using Sustainsys.Saml2.Saml2P;
using Sustainsys.Saml2.Tokens;
using System;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Sustainsys.Saml2.Metadata.Exceptions;
using Sustainsys.Saml2.Metadata.Tokens;

namespace Sustainsys.Saml2.WebSso
{
    class Saml2RedirectBinding : Saml2Binding
    {
        public override CommandResult Bind(ISaml2Message message, ILoggerAdapter logger)
        {
            return Bind(message, logger, null);
        }

        public override CommandResult Bind<TMessage>(
            TMessage message, ILoggerAdapter logger, Action<TMessage, XDocument, Saml2BindingType> xmlCreatedNotification)
        {
            if (message == null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            var messageXml = message.ToXml(xd => xmlCreatedNotification?.Invoke(message, xd, Saml2BindingType.HttpRedirect));
            logger?.WriteVerbose("Sending message over Http Redirect Binding\n" + messageXml);

            var serializedRequest = Serialize(messageXml);

            var queryString = message.MessageName + "=" + serializedRequest
                + (string.IsNullOrEmpty(message.RelayState) ? ""
                    : ("&RelayState=" + Uri.EscapeDataString(message.RelayState)));

            if (message.SigningCertificate != null)
            {
                queryString = AddSignature(queryString, message);
            }

            var redirectUri = new Uri(message.DestinationUrl.ToString()
                + (string.IsNullOrEmpty(message.DestinationUrl.Query) ? "?" : "&")
                + queryString);

            return new CommandResult()
            {
                HttpStatusCode = HttpStatusCode.SeeOther,
                Location = redirectUri
            };
        }

        private static string AddSignature(string queryString, ISaml2Message message)
        {
            string signingAlgorithmUrl = message.SigningAlgorithm;

            queryString += "&SigAlg=" + Uri.EscapeDataString(signingAlgorithmUrl);
            var signatureDescription = (SignatureDescription)CryptographyExtensions.CreateAlgorithmFromName(signingAlgorithmUrl);
            HashAlgorithm hashAlg = signatureDescription.CreateDigest();
            hashAlg.ComputeHash(Encoding.UTF8.GetBytes(queryString));
            var signingKey = message.SigningCertificate.PrivateKey.GetSha256EnabledAsymmetricAlgorithm();
            AsymmetricSignatureFormatter asymmetricSignatureFormatter =signatureDescription.CreateFormatter(signingKey);
            byte[] signatureValue = asymmetricSignatureFormatter.CreateSignature(hashAlg);
            queryString += "&Signature=" + Uri.EscapeDataString(Convert.ToBase64String(signatureValue));
            return queryString;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2202:Do not dispose objects multiple times", Justification = "The MemoryStream is not disposed by the DeflateStream - we're using the keep-open flag.")]
        public override UnbindResult Unbind(HttpRequestData request, IOptions options)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var encodedPayload = request.QueryString["SAMLRequest"].FirstOrDefault() ?? request.QueryString["SAMLResponse"].First();
            try
            {
                var payload = Convert.FromBase64String(encodedPayload);

                using (var compressed = new MemoryStream(payload))
                {
                    using (var decompressedStream = new DeflateStream(compressed, CompressionMode.Decompress, true))
                    {
                        using (var deCompressed = new MemoryStream())
                        {
                            decompressedStream.CopyTo(deCompressed);

                            var xml = XmlHelpers.XmlDocumentFromString(
                                Encoding.UTF8.GetString(deCompressed.GetBuffer(), 0, (int)deCompressed.Length));

                            options?.SPOptions.Logger.WriteVerbose("Http Redirect binding extracted message\n" + xml.OuterXml);

                            return new UnbindResult(xml.DocumentElement, request.QueryString["RelayState"].SingleOrDefault(), GetTrustLevel(xml.DocumentElement, request, options));
                        }
                    }
                }
            }
            catch(FormatException ex)
            {
                throw new FormatException($"\'{encodedPayload}\' is not a valid Base64 encoded string: {ex.Message}", ex);
            }
        }

        private static TrustLevel GetTrustLevel(XmlElement documentElement, HttpRequestData request, IOptions options)
        {
            if (options == null)
            {
                return TrustLevel.None;
            }

            if (!request.QueryString["SigAlg"].Any())
            {
                return TrustLevel.None;
            }

            var issuer = documentElement["Issuer", Saml2Namespaces.Saml2Name]?.InnerText;

            if (string.IsNullOrEmpty(issuer))
            {
                return TrustLevel.None;
            }

            if (!options.IdentityProviders.TryGetValue(new EntityId(issuer), out IdentityProvider idp))
            {
                throw new InvalidSignatureException(string.Format(CultureInfo.InvariantCulture, "Cannot verify signature of message from unknown sender {0}.", issuer));
            }

            CheckSignature(request, idp, options);

            return TrustLevel.Signature;
        }

        private static void CheckSignature(HttpRequestData request, IdentityProvider idp, IOptions options)
        {
            // Can't use the query string params as found in HttpReqeustData
            // because they are already unescaped and we need the exact format
            // of the original data.
            var rawQueryStringParams = request.Url.Query.TrimStart('?').Split('&').Select(qp => qp.Split('=')).ToDictionary(kv => kv[0], kv => kv[1]);

            var msgParam = "";
            if (rawQueryStringParams.TryGetValue("SAMLRequest", out string msg))
            {
                msgParam = "SAMLRequest=" + msg;
            }
            else
            {
                msgParam = "SAMLResponse=" + rawQueryStringParams["SAMLResponse"];
            }

            var relayStateParam = "";
            if (rawQueryStringParams.TryGetValue("RelayState", out string relayState))
            {
                relayStateParam = "&RelayState=" + relayState;
            }

            var signedString = string.Format(CultureInfo.InvariantCulture, "{0}{1}&SigAlg={2}", msgParam, relayStateParam, rawQueryStringParams["SigAlg"]);

            var sigAlg = request.QueryString["SigAlg"].Single();

            XmlHelpers.ValidateSignatureMethodStrength(options.SPOptions.MinIncomingSigningAlgorithm, sigAlg);

            var signatureDescription = (SignatureDescription)CryptographyExtensions.CreateAlgorithmFromName(sigAlg);

            var hashAlg = signatureDescription.CreateDigest();
            hashAlg.ComputeHash(Encoding.UTF8.GetBytes(signedString));

            var signature = Convert.FromBase64String(request.QueryString["Signature"].Single());

            if (!idp.SigningKeys.Any(kic => signatureDescription.CreateDeformatter(((AsymmetricSecurityKey)kic.CreateKey()).GetAsymmetricAlgorithm(sigAlg, false)).VerifySignature(hashAlg, signature)))
            {
                throw new InvalidSignatureException(string.Format(CultureInfo.InvariantCulture, "Message from {0} failed signature verification", idp.EntityId.Id));
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2202:Do not dispose objects multiple times", Justification = "The MemoryStream is not disposed by the DeflateStream - we're using the keep-open flag.")]
        private static string Serialize(string payload)
        {
            using (var compressed = new MemoryStream())
            {
                using (var writer = new StreamWriter(new DeflateStream(compressed, CompressionLevel.Optimal, true)))
                {
                    writer.Write(payload);
                }

                return Uri.EscapeDataString(Convert.ToBase64String(compressed.GetBuffer(), 0, (int)compressed.Length));
            }
        }

        protected internal override bool CanUnbind(HttpRequestData request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            return (request.QueryString["SAMLRequest"].Any() || request.QueryString["SAMLResponse"].Any());
        }
    }
}
