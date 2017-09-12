using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;
using NSubstitute;
using Kentor.AuthServices.Metadata;

namespace Kentor.AuthServices.Tests.Metadata
{
    [TestClass]
    public class MetadataRefreshSchedulerTests
    {
        [TestMethod]
        public void MetadataRefreshScheduler_GetDelay_ReturnsHalfRemaining()
        {
            var validUntil = DateTime.UtcNow.AddHours(2);

            var subject = MetadataRefreshScheduler.GetDelay(validUntil);

            subject.Should().BeCloseTo(new TimeSpan(1, 0, 0));
        }

        [TestMethod]
        public void MetadataRefreshScheduler_GetDelay_RespectsMinInterval()
        {
            var validUntil = DateTime.UtcNow.AddSeconds(10);

            var subject = MetadataRefreshScheduler.GetDelay(validUntil);

            subject.Should().BeCloseTo(new TimeSpan(0, 1, 0));
        }

        [TestMethod]
        public void MetadataRefreshScheduler_GetDelay_RespectsMaxInterval()
        {
            var validUntil = new DateTime(2100, 01, 01);

            var subject = MetadataRefreshScheduler.GetDelay(validUntil);

            var maxDelay = new TimeSpan(0, 0, 0, 0, int.MaxValue);

            subject.Should().BeCloseTo(maxDelay);
        }

        [TestMethod]
        public void MetadataRefreshScheduler_CalculateMetadataValidUntil_ValidUntilExists_CacheDurationExists()
        {
            var metadata = Substitute.For<ICachedMetadata>();
            metadata.ValidUntil = new DateTime(2100, 01, 01);
            metadata.CacheDuration = MetadataRefreshScheduler.DefaultMetadataCacheDuration;

            var subject = metadata.CalculateMetadataValidUntil();

            subject.Should().Be(new DateTime(2100, 01, 01));
        }

        [TestMethod]
        public void MetadataRefreshScheduler_CalculateMetadataValidUntil_ValidUntilMissing_CacheDurationExists()
        {
            var metadata = Substitute.For<ICachedMetadata>();
            metadata.ValidUntil = null;
            metadata.CacheDuration = MetadataRefreshScheduler.DefaultMetadataCacheDuration;            

            var subject = metadata.CalculateMetadataValidUntil();

            subject.Should().BeCloseTo(DateTime.UtcNow.AddHours(4));
        }

        [TestMethod]
        public void MetadataRefreshScheduler_CalculateMetadataValidUntil_ValidUntilExists_CacheDurationMissing()
        {
            var metadata = Substitute.For<ICachedMetadata>();
            metadata.ValidUntil = new DateTime(2100, 01, 01);
            metadata.CacheDuration = null;

            var subject = metadata.CalculateMetadataValidUntil();

            subject.Should().Be(new DateTime(2100, 01, 01));
        }

        [TestMethod]
        public void MetadataRefreshScheduler_CalculateMetadataValidUntil_ValidUntilMissing_CacheDurationMissing()
        {
            var metadata = Substitute.For<ICachedMetadata>();
            metadata.ValidUntil = null;
            metadata.CacheDuration = null;

            var subject = metadata.CalculateMetadataValidUntil();

            subject.Should().BeCloseTo(DateTime.UtcNow.AddDays(1), precision: 100);
        }

        [TestMethod]
        public void MetadataRefreshScheduler_CalculateMetadataCacheDuration_ValidUntilExists_CacheDurationExists()
        {
            var metadata = Substitute.For<ICachedMetadata>();
            metadata.ValidUntil = new DateTime(2100, 01, 01);
            metadata.CacheDuration = MetadataRefreshScheduler.DefaultMetadataCacheDuration;

            var subject = metadata.CalculateMetadataCacheDuration();

            subject.Should().Be(new TimeSpan(1, 0, 0));
        }

        [TestMethod]
        public void MetadataRefreshScheduler_CalculateMetadataCacheDuration_ValidUntilMissing_CacheDurationExists()
        {
            var metadata = Substitute.For<ICachedMetadata>();
            metadata.ValidUntil = null;
            metadata.CacheDuration = MetadataRefreshScheduler.DefaultMetadataCacheDuration;

            var subject = metadata.CalculateMetadataCacheDuration();

            subject.Should().Be(new TimeSpan(1, 0, 0));
        }

        [TestMethod]
        public void MetadataRefreshScheduler_CalculateMetadataCacheDuration_ValidUntilExists_CacheDurationMissing()
        {
            var metadata = Substitute.For<ICachedMetadata>();
            metadata.ValidUntil = DateTime.UtcNow.AddHours(1);
            metadata.CacheDuration = null;

            var subject = metadata.CalculateMetadataCacheDuration();

            subject.Should().BeCloseTo(new TimeSpan(0, 15, 0));
        }

        [TestMethod]
        public void MetadataRefreshScheduler_CalculateMetadataCacheDuration_ShortValidUntil_CacheDurationMissing()
        {
            var metadata = Substitute.For<ICachedMetadata>();
            metadata.ValidUntil = DateTime.UtcNow.AddMinutes(3);
            metadata.CacheDuration = null;

            var subject = metadata.CalculateMetadataCacheDuration();

            subject.Should().BeCloseTo(new TimeSpan(0, 2, 0));
        }

        [TestMethod]
        public void MetadataRefreshScheduler_CalculateMetadataCacheDuration_LongValidUntil_CacheDurationMissing()
        {
            var metadata = Substitute.For<ICachedMetadata>();
            metadata.ValidUntil = DateTime.UtcNow.AddHours(12);
            metadata.CacheDuration = null;

            var subject = metadata.CalculateMetadataCacheDuration();

            subject.Should().Be(MetadataRefreshScheduler.DefaultMetadataCacheDuration);
        }

        [TestMethod]
        public void MetadataRefreshScheduler_CalculateMetadataCacheDuration_ValidUntilMissing_CacheDurationMissing()
        {
            var metadata = Substitute.For<ICachedMetadata>();
            metadata.ValidUntil = null;
            metadata.CacheDuration = null;

            var subject = metadata.CalculateMetadataCacheDuration();

            subject.Should().Be(new TimeSpan(1, 0, 0));
        }
    }
}
