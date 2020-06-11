using Sustainsys.Saml2.Saml2P;
using Sustainsys.Saml2.WebSso;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Configuration;
using System.IdentityModel.Metadata;
using Sustainsys.Saml2.Metadata;
using Microsoft.IdentityModel.Tokens.Saml2;
using System.Linq;
using System.Security.Claims;
using ClaimProperties = Microsoft.IdentityModel.Tokens.Saml2.ClaimProperties;

namespace Sustainsys.Saml2.StubIdp.Models
{
    public class AssertionModel
    {
        [Required]
        [Display(Name = "Assertion Consumer Service Url")]
        public string AssertionConsumerServiceUrl { get; set; }

        [Display(Name = "Relay State")]
        [StringLength(1024)]
        public string RelayState { get; set; }

        [Display(Name = "Subject NameId")]
        [Required]
        public string NameId { get; set; }

        [Display(Name = "Audience")]
        public string Audience { get; set; }

        public ICollection<AttributeStatementModel> AttributeStatements { get; set; }

        public const string DefaultSessionIndex = "42";

        /// <summary>
        /// Creates a new Assertion model with values from web.config
        /// </summary>
        /// <returns>An <see cref="AssertionModel"/></returns>
        public static AssertionModel CreateFromConfiguration()
        {
            return new AssertionModel
            {
                AssertionConsumerServiceUrl = ConfigurationManager.AppSettings["defaultAcsUrl"],
                NameId = ConfigurationManager.AppSettings["defaultNameId"],
                SessionIndex = DefaultSessionIndex
            };
        }

        [Display(Name = "In Response To ID")]
        public string InResponseTo { get; set; }

        private static IEnumerable<string> YieldIfNotNullOrEmpty(string src)
        {
            if(!string.IsNullOrEmpty(src))
            {
                yield return src;
            }
        }

        public Saml2Response ToSaml2Response()
        {
            var nameIdClaim = new Claim(ClaimTypes.NameIdentifier, NameId);
            nameIdClaim.Properties[ClaimProperties.SamlNameIdentifierFormat] = 
                NameIdFormat.Unspecified.GetUri().AbsoluteUri;
            var claims =
                new Claim[] { nameIdClaim }
                .Concat(YieldIfNotNullOrEmpty(SessionIndex).Select(
                    s => new Claim(Saml2ClaimTypes.SessionIndex, SessionIndex)))
                .Concat((AttributeStatements ?? Enumerable.Empty<AttributeStatementModel>())
                    .Select(att => new Claim(att.Type, att.Value)));
            var identity = new ClaimsIdentity(claims);

            Saml2Id saml2Id = null;
            if (!string.IsNullOrEmpty(InResponseTo))
            {
                saml2Id = new Saml2Id(InResponseTo);
            }
            
            var audienceUrl = string.IsNullOrEmpty(Audience)
                ? null
                : new Uri(Audience);

            return new Saml2Response(
                new Metadata.EntityId(UrlResolver.MetadataUrl.ToString()),
                CertificateHelper.SigningCertificate, new Uri(AssertionConsumerServiceUrl),
                saml2Id, RelayState, audienceUrl, identity);
        }

        [Display(Name = "Incoming AuthnRequest")]
        public string AuthnRequestXml { get; set; }

        public Saml2BindingType ResponseBinding { get; set; } = Saml2BindingType.HttpPost;

        [Display(Name = "Session Index")]
        public string SessionIndex { get; set; }
    }
}