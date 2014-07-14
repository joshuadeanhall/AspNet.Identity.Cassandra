using System;
using FluentAssertions;
using Microsoft.AspNet.Identity;
using NUnit.Framework;

namespace AspNet.Identity.Cassandra.IntegrationTests
{
    /// <summary>
    /// Tests around failed access and lockouts.
    /// </summary>
    [TestFixture]
    public class LockoutTests : IntegrationTestBase
    {
        public override void TestSetup()
        {
            base.TestSetup();
            UserManager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(15);
            UserManager.MaxFailedAccessAttemptsBeforeLockout = 1;
        }

        [Test]
        public async void GetSetLockoutEnabled()
        {
            // Create a user
            var user = new CassandraUser(Guid.NewGuid()) {UserName = "lockoutUser1"};
            await UserManager.CreateAsync(user);

            // Lockout should not be enabled by default
            bool isLockoutEnabled = await UserManager.GetLockoutEnabledAsync(user.Id);
            isLockoutEnabled.Should().BeFalse();

            // Should be able to turn on lockout for a user
            IdentityResult result = await UserManager.SetLockoutEnabledAsync(user.Id, true);
            result.ShouldBeSuccess();

            // Should now be enabled
            isLockoutEnabled = await UserManager.GetLockoutEnabledAsync(user.Id);
            isLockoutEnabled.Should().BeTrue();
        }

        [Test]
        public async void GetSetLockoutEndDate()
        {
            // Create a user and enable lockout
            var user = new CassandraUser(Guid.NewGuid()) { UserName = "lockoutUser2" };
            await UserManager.CreateAsync(user);
            await UserManager.SetLockoutEnabledAsync(user.Id, true);

            // Should be able to set lockout end date
            DateTimeOffset lockoutDate = DateTimeOffset.UtcNow;
            IdentityResult result = await UserManager.SetLockoutEndDateAsync(user.Id, lockoutDate);
            result.ShouldBeSuccess();

            // Should be able to retrieve that lockout date
            DateTimeOffset lookupDate = await UserManager.GetLockoutEndDateAsync(user.Id);
            lookupDate.Should().BeCloseTo(lockoutDate);     // Use CloseTo because C* is not accurate down to the ticks level
        }

        [Test]
        public async void LockUserOut()
        {
            // Create a user and enable lockout
            var user = new CassandraUser(Guid.NewGuid()) {UserName = "lockoutUser3"};
            await UserManager.CreateAsync(user);
            await UserManager.SetLockoutEnabledAsync(user.Id, true);

            // Should be able to record a failed login
            IdentityResult result = await UserManager.AccessFailedAsync(user.Id);
            result.ShouldBeSuccess();

            // Since the test setup uses one as the threshold for lockouts, the user should now be locked out
            bool isLockedOut = await UserManager.IsLockedOutAsync(user.Id);
            isLockedOut.Should().BeTrue();

            // Since the test setup set the lockout period to 15 mins, the lockout end date should be approximately 15 mins from now
            DateTimeOffset lockoutEndDate = await UserManager.GetLockoutEndDateAsync(user.Id);
            lockoutEndDate.Should().BeCloseTo(DateTimeOffset.UtcNow.Add(15.Minutes()), precision: 1000);    // 1000 == Within 1 second
        }
    }
}
