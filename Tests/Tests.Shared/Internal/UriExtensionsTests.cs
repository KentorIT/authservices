using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;
using Sustainsys.Saml2.Internal;

namespace Sustainsys.Saml2.Tests.Internal {
    [TestClass]
    public class UriExtensionsTests {
        
        [TestMethod]
        public void ExtractIdFromLocalUri_DefaultUri_RemovedHash() {
            var subject = UriExtensions.ExtractIdFromLocalUri("#_cda7be982d6d9c1052f7f8d439869c8f");
            subject.Should().Be("_cda7be982d6d9c1052f7f8d439869c8f");
        }

        [TestMethod]
        public void ExtractIdFromLocalUri_UriWithSlash_RemovedHashAndSlash() {
            var subject = UriExtensions.ExtractIdFromLocalUri("#_cda7be982d6d9c1052f7f8d439869c8f\'");
            subject.Should().Be("_cda7be982d6d9c1052f7f8d439869c8f'");
        }

        [TestMethod]
        public void ExtractIdFromLocalUri_UriWithXPointer_RemovedHashAndIdString() {
            var subject = UriExtensions.ExtractIdFromLocalUri("#xpointer(id(cda7be982d6d9c1052f7f8d439869c8f)ss");
            subject.Should().Be("cda7be982d6d9c1052f7f8d439869c8f");
        }
    }
}
