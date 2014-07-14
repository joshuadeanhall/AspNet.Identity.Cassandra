using System;
using FluentAssertions;
using Microsoft.AspNet.Identity;
using NUnit.Framework;

namespace AspNet.Identity.Cassandra.IntegrationTests
{
    /// <summary>
    /// Tests for storing, authenticating, and changing user passwords.
    /// </summary>
    [TestFixture]
    public class PasswordTests : IntegrationTestBase
    {
        public override void TestSetup()
        {
            base.TestSetup();
            UserManager.UserTokenProvider = new TotpSecurityStampBasedTokenProvider<CassandraUser, Guid>();
        }

        [Test]
        public async void HasPassword()
        {
            // Create a user
            var user = new CassandraUser(Guid.NewGuid()) { UserName = "passwordUser1" };
            await UserManager.CreateAsync(user);

            // Verify they are created without a password
            bool hasPassword = await UserManager.HasPasswordAsync(user.Id);
            hasPassword.Should().BeFalse();

            // Create a user with a password
            user = new CassandraUser(Guid.NewGuid()) {UserName = "passwordUser2"};
            await UserManager.CreateAsync(user, "somePassword");

            // Verify they have a password
            hasPassword = await UserManager.HasPasswordAsync(user.Id);
            hasPassword.Should().BeTrue();
        }

        [Test]
        public async void AddRemovePassword()
        {
            // Create user without password
            var user = new CassandraUser(Guid.NewGuid()) {UserName = "passwordUser3"};
            await UserManager.CreateAsync(user);

            // Adding a password should succeed
            IdentityResult result = await UserManager.AddPasswordAsync(user.Id, "somePassword");
            result.ShouldBeSuccess();
            bool hasPassword = await UserManager.HasPasswordAsync(user.Id);
            hasPassword.Should().BeTrue();

            // Now removing a password should succeed
            result = await UserManager.RemovePasswordAsync(user.Id);
            result.ShouldBeSuccess();
            hasPassword = await UserManager.HasPasswordAsync(user.Id);
            hasPassword.Should().BeFalse();
        }

        [Test]
        public async void Authenticate()
        {
            // Create a user with a password
            var user = new CassandraUser(Guid.NewGuid()) {UserName = "passwordUser4"};
            await UserManager.CreateAsync(user, "somePassword");

            // Should be able to authenticate user with password
            bool authenticated = await UserManager.CheckPasswordAsync(user, "somePassword");
            authenticated.Should().BeTrue();
        }

        [Test]
        public async void ChangePassword()
        {
            // Create a user with a password
            var user = new CassandraUser(Guid.NewGuid()) { UserName = "passwordUser5" };
            await UserManager.CreateAsync(user, "somePassword");

            // Should be able to change the password
            IdentityResult result = await UserManager.ChangePasswordAsync(user.Id, "somePassword", "someNewPassword");
            result.ShouldBeSuccess();

            // Should be able to authenticate with new password
            user = await UserManager.FindByIdAsync(user.Id);
            bool authenticated = await UserManager.CheckPasswordAsync(user, "someNewPassword");
            authenticated.Should().BeTrue();

            // Should not be able to authenticate with old password
            authenticated = await UserManager.CheckPasswordAsync(user, "somePassword");
            authenticated.Should().BeFalse();
        }

        [Test]
        public async void ResetPassword()
        {
            // Create a user with a password
            var user = new CassandraUser(Guid.NewGuid()) { UserName = "passwordUser6" };
            await UserManager.CreateAsync(user, "somePassword");

            // Generate a reset token and then reset the password should succeed
            string token = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
            IdentityResult result = await UserManager.ResetPasswordAsync(user.Id, token, "someNewPassword");
            result.ShouldBeSuccess();

            // Should now be able to authenticate with new password
            user = await UserManager.FindByIdAsync(user.Id);
            bool authenticated = await UserManager.CheckPasswordAsync(user, "someNewPassword");
            authenticated.Should().BeTrue();

            // Should not be able to authenticate with old password
            authenticated = await UserManager.CheckPasswordAsync(user, "somePassword");
            authenticated.Should().BeFalse();
        }
    }
}
