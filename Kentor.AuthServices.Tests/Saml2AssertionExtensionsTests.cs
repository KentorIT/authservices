﻿using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IdentityModel.Tokens;
using FluentAssertions;
using System.Collections.ObjectModel;

namespace Kentor.AuthServices.Tests
{
    [TestClass]
    public class Saml2AssertionExtensionsTests
    {
        [TestMethod]
        public void Saml2AssertionExtensions_ToXElement_NullCheck()
        {
            Saml2Assertion assertion = null;

            Action a = () => assertion.ToXElement();

            a.ShouldThrow<ArgumentNullException>().And.ParamName.Should().Be("assertion");
        }

        [TestMethod]
        public void Saml2AssertionExtensions_ToXElement_Xml_BasicAttributes()
        {
            // Grab the current time before and after creating the assertion to
            // handle the unlikely event that the second part of the date time
            // is incremented during the test run. We don't want any heisenbugs.
            var before = DateTime.UtcNow.ToString("s") + "Z";

            var issuer = "http://idp.example.com";
            var assertion = new Saml2Assertion(new Saml2NameIdentifier(issuer));

            var after = DateTime.UtcNow.ToString("s") + "Z";

            var subject = assertion.ToXElement();

            subject.ToString().Should().StartWith(
                @"<saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion");
            subject.Attribute("Version").Value.Should().Be("2.0");
            subject.Attribute("ID").Value.Should().NotBeBlank();
            subject.Attribute("IssueInstant").Value.Should().Match(
                i => i == before || i == after);
        }

        [TestMethod]
        public void Saml2AssertionExtensions_ToXElement_Issuer()
        {
            var issuer = "http://idp.example.com";
            var assertion = new Saml2Assertion(new Saml2NameIdentifier(issuer));

            var subject = assertion.ToXElement();

            subject.Element(Saml2Namespaces.Saml2 + "Issuer").Value.Should().Be(issuer);
        }

        [TestMethod]
        public void Saml2AssertionExtensions_ToXElement_Subject()
        {
            var subjectName = "JohnDoe";
            var assertion = new Saml2Assertion(
                new Saml2NameIdentifier("http://idp.example.com"))
                {
                    Subject = new Saml2Subject(new Saml2NameIdentifier(subjectName))
                };

            var subject = assertion.ToXElement();

            subject.Element(Saml2Namespaces.Saml2 + "Subject").
                Element(Saml2Namespaces.Saml2 + "NameID").Value.Should().Be(subjectName);

            // Although SubjectConfirmation is optional in the SAML core spec, it is
            // mandatory in the Web Browser SSO Profile and must have a value of bearer.
            subject.Element(Saml2Namespaces.Saml2 + "Subject").
                Element(Saml2Namespaces.Saml2 + "SubjectConfirmation")
                .Attribute("Method").Value.Should().Be("urn:oasis:names:tc:SAML:2.0:cm:bearer");
        }

        [TestMethod]
        public void Saml2AssertionExtensions_ToXElement_Conditions()
        {
            var assertion = new Saml2Assertion(
                new Saml2NameIdentifier("http://idp.example.com"))
            {
                Conditions = new Saml2Conditions()
                {
                    NotOnOrAfter = new DateTime(2099, 07, 25, 19, 52, 42, DateTimeKind.Utc)
                }
            };

            var subject = assertion.ToXElement();

            subject.Element(Saml2Namespaces.Saml2 + "Conditions")
                .Attribute("NotOnOrAfter").Value.Should().Be("2099-07-25T19:52:42Z");
        }
    }
}
