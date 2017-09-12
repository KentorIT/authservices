using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Kentor.AuthServices.Metadata
{
    internal static class MetadataRefreshScheduler
    {
        internal static TimeSpan minInterval = new TimeSpan(0, 1, 0);

        // Maximum delay supported by Task.Delay()
        private static readonly TimeSpan maxInterval = new TimeSpan(0, 0, 0, 0, int.MaxValue);

        internal static TimeSpan GetDelay(DateTime validUntil)
        {
            var timeRemaining = validUntil - DateTime.UtcNow;
            var delay = new TimeSpan(timeRemaining.Ticks / 2);

            if (delay < minInterval)
            {
                return minInterval;
            }

            if (delay > maxInterval)
            {
                return maxInterval;
            }

            return delay;
        }

        internal static TimeSpan CalculateMetadataCacheDuration(this ICachedMetadata metadata)
        {
            if (metadata.CacheDuration.HasValue)
            {
                return (TimeSpan)metadata.CacheDuration;
            }

            if (metadata.ValidUntil.HasValue)
            {
                return CalculateCacheDurationFromValidUntil(metadata.ValidUntil.Value);
            }

            return DefaultMetadataCacheDuration;
        }

        private static TimeSpan CalculateCacheDurationFromValidUntil(DateTime validUntil)
        {
            var timeRemaining = validUntil - DateTime.UtcNow;
            var twoMinutes = new TimeSpan(0, 2, 0).Ticks;
            return new TimeSpan(Math.Max(Math.Min(DefaultMetadataCacheDuration.Ticks, timeRemaining.Ticks / 4), twoMinutes));
        }

        public static readonly TimeSpan DefaultMetadataCacheDuration = new TimeSpan(1, 0, 0);

        internal static DateTime CalculateMetadataValidUntil(this ICachedMetadata metadata)
        {
            if (metadata.ValidUntil.HasValue)
            {
                return (DateTime)metadata.ValidUntil;
            }

            if (metadata.CacheDuration.HasValue)
            {
                var extendedCacheDuration = metadata.CacheDuration.Value.Ticks * 4;
                return DateTime.UtcNow.Add(new TimeSpan(extendedCacheDuration));
            }

            return DateTime.UtcNow.AddDays(1);
        }        
    }
}
