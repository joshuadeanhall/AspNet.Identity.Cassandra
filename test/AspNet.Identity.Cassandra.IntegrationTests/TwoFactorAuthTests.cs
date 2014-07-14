using System;
using FluentAssertions;
using Microsoft.AspNet.Identity;
using NUnit.Framework;

namespace AspNet.Identity.Cassandra.IntegrationTests
{
    /// <summary>
    /// Tests for 2FA.
    /// </summary>
    [TestFixture]
    public class TwoFactorAuthTests : IntegrationTestBase
    {
        [Test]
        public async void EnableDisableTwoFactor()
        {
            // Create a user
            var user = new CassandraUser(Guid.NewGuid()) {UserName = "twoFactorUser1"};
            await UserManager.CreateAsync(user);

            // 2FA should be disabled by default
            bool isEnabled = await UserManager.GetTwoFactorEnabledAsync(user.Id);
            isEnabled.Should().BeFalse();

            // Can set 2FA enabled
            IdentityResult result = await UserManager.SetTwoFactorEnabledAsync(user.Id, true);
            result.ShouldBeSuccess();

            // Should be enabled now
            isEnabled = await UserManager.GetTwoFactorEnabledAsync(user.Id);
            isEnabled.Should().BeTrue();
        }
    }
}