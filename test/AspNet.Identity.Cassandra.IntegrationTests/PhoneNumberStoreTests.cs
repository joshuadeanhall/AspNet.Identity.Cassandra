using System;
using FluentAssertions;
using Microsoft.AspNet.Identity;
using NUnit.Framework;

namespace AspNet.Identity.Cassandra.IntegrationTests
{
    /// <summary>
    /// Tests storage/confirmation of phone numbers.
    /// </summary>
    [TestFixture]
    public class PhoneNumberStoreTests : IntegrationTestBase
    {
        public override void TestSetup()
        {
            base.TestSetup();
            UserManager.UserTokenProvider = new TotpSecurityStampBasedTokenProvider<CassandraUser, Guid>();
        }

        [Test]
        public async void GetSetPhoneNumber()
        {
            // Create a user
            var user = new CassandraUser(Guid.NewGuid()) {UserName = "phoneUser1"};
            await UserManager.CreateAsync(user);

            // Should not have phone number by default
            string phoneNumber = await UserManager.GetPhoneNumberAsync(user.Id);
            phoneNumber.Should().BeNullOrEmpty();

            // Can set phone number
            const string phone = "555-555-1212";
            IdentityResult result = await UserManager.SetPhoneNumberAsync(user.Id, phone);
            result.ShouldBeSuccess();

            // Should now have phone number
            phoneNumber = await UserManager.GetPhoneNumberAsync(user.Id);
            phoneNumber.Should().Be(phone);
        }

        [Test]
        public async void PhoneNumberConfirmation()
        {
            // Create a user with a phone number
            const string phone = "555-555-1212";
            var user = new CassandraUser(Guid.NewGuid()) { UserName = "phoneUser2" };
            await UserManager.CreateAsync(user);
            await UserManager.SetPhoneNumberAsync(user.Id, phone);

            // Should not be confirmed by default
            bool isConfirmed = await UserManager.IsPhoneNumberConfirmedAsync(user.Id);
            isConfirmed.Should().BeFalse();

            // Generate a token to verify the phone number
            string token = await UserManager.GenerateChangePhoneNumberTokenAsync(user.Id, phone);
            IdentityResult result = await UserManager.ChangePhoneNumberAsync(user.Id, phone, token);
            result.ShouldBeSuccess();

            // Phone number should now be confirmed
            isConfirmed = await UserManager.IsPhoneNumberConfirmedAsync(user.Id);
            isConfirmed.Should().BeTrue();
        }
    }
}
