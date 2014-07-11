using System;
using FluentAssertions;
using Microsoft.AspNet.Identity;
using NUnit.Framework;

namespace AspNet.Identity.Cassandra.IntegrationTests
{
    /// <summary>
    /// Some tests for Email storage functionality, including finding by email.
    /// </summary>
    [TestFixture]
    public class EmailStoreTests : IntegrationTestBase
    {
        public override void TestSetup()
        {
            base.TestSetup();
            UserManager.UserTokenProvider = new TotpSecurityStampBasedTokenProvider<CassandraUser, Guid>();
        }
        
        [Test]
        public async void GetAndSetEmail()
        {
            // Create a user
            var user = new CassandraUser(Guid.NewGuid()) { UserName = "emailUser1" };
            await UserManager.CreateAsync(user);

            // User should not have an email address initially
            string userEmail = await UserManager.GetEmailAsync(user.Id);
            userEmail.Should().BeNullOrEmpty();

            // Set email address for user
            const string email = "emailUser1@test.com";
            IdentityResult result = await UserManager.SetEmailAsync(user.Id, email);
            result.ShouldBeSuccess();

            // Now user should have email
            userEmail = await UserManager.GetEmailAsync(user.Id);
            userEmail.Should().Be(email);
        }

        [Test]
        public async void FindByEmail()
        {
            // Create a user and set their email address
            const string email = "emailUser2@test.com";
            var user = new CassandraUser(Guid.NewGuid()) { UserName = "emailUser2" };
            await UserManager.CreateAsync(user);
            await UserManager.SetEmailAsync(user.Id, email);
            
            // User should be able to be looked up by email
            CassandraUser foundUser = await UserManager.FindByEmailAsync(email);
            foundUser.ShouldBeEquivalentToUser(user);

            // Delete the user
            await UserManager.DeleteAsync(foundUser);

            // User should no longer be able to be found by email
            foundUser = await UserManager.FindByEmailAsync(email);
            foundUser.Should().BeNull();
        }

        [Test]
        public async void ChangeEmail()
        {
            // Create a user and set their email address
            const string email = "emailUser3@test.com";
            var user = new CassandraUser(Guid.NewGuid()) { UserName = "emailUser3" };
            await UserManager.CreateAsync(user);
            await UserManager.SetEmailAsync(user.Id, email);

            // Change their email address
            const string newEmail = "emailUser3@someotherdomain.com";
            IdentityResult result = await UserManager.SetEmailAsync(user.Id, newEmail);
            result.ShouldBeSuccess();

            // Should not be able to find the user by the old email address
            CassandraUser foundUser = await UserManager.FindByEmailAsync(email);
            foundUser.Should().BeNull();

            // Should be able to find the user by the new email address
            foundUser = await UserManager.FindByEmailAsync(newEmail);
            foundUser.ShouldBeEquivalentToUser(user);
        }

        [Test]
        public async void EmailConfirmation()
        {
            // Create a user and set their email address
            const string email = "emailUser4@test.com";
            var user = new CassandraUser(Guid.NewGuid()) { UserName = "emailUser4" };
            await UserManager.CreateAsync(user);
            await UserManager.SetEmailAsync(user.Id, email);

            // Email should NOT be confirmed by default
            bool confirmed = await UserManager.IsEmailConfirmedAsync(user.Id);
            confirmed.Should().BeFalse();

            // Generate a token and confirm the email
            string token = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);
            IdentityResult result = await UserManager.ConfirmEmailAsync(user.Id, token);
            result.ShouldBeSuccess();

            // Email should now be confirmed
            confirmed = await UserManager.IsEmailConfirmedAsync(user.Id);
            confirmed.Should().BeTrue();
        }
    }
}
