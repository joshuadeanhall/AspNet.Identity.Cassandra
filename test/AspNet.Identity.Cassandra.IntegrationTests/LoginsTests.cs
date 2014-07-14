using System;
using System.Collections.Generic;
using System.Linq;
using FluentAssertions;
using Microsoft.AspNet.Identity;
using NUnit.Framework;

namespace AspNet.Identity.Cassandra.IntegrationTests
{
    /// <summary>
    /// Tests for external login storage.
    /// </summary>
    [TestFixture]
    public class LoginsTests : IntegrationTestBase
    {
        [Test]
        public async void AddRemoveLogins()
        {
            // Create a user
            var user = new CassandraUser(Guid.NewGuid()) { UserName = "externalLoginUser1" };
            await UserManager.CreateAsync(user);

            // Should not have any logins intially
            IList<UserLoginInfo> logins = await UserManager.GetLoginsAsync(user.Id);
            logins.Should().BeEmpty();

            // Add some logins for the user and make sure we can retrieve them
            var loginsToAdd = new[]
            {
                new UserLoginInfo("facebook", Guid.NewGuid().ToString()),
                new UserLoginInfo("google", Guid.NewGuid().ToString())
            };

            IdentityResult result;
            foreach (UserLoginInfo login in loginsToAdd)
            {
                result = await UserManager.AddLoginAsync(user.Id, login);
                result.ShouldBeSuccess();
            }

            logins = await UserManager.GetLoginsAsync(user.Id);
            logins.Should().NotBeEmpty()
                  .And.HaveCount(loginsToAdd.Length);
            logins.ShouldAllBeEquivalentTo(loginsToAdd);

            // Now remove one of the logins from the user
            result = await UserManager.RemoveLoginAsync(user.Id, loginsToAdd[0]);
            result.ShouldBeSuccess();

            logins = await UserManager.GetLoginsAsync(user.Id);
            logins.Should().NotBeEmpty()
                  .And.HaveCount(loginsToAdd.Length - 1);
            logins.ShouldAllBeEquivalentTo(loginsToAdd.Where((_, idx) => idx != 0));
        }

        [Test]
        public async void FindByLogin()
        {
            // Create a user and add a login to the user
            var user = new CassandraUser(Guid.NewGuid()) { UserName = "externalLoginUser2" };
            await UserManager.CreateAsync(user);

            var login = new UserLoginInfo("facebook", Guid.NewGuid().ToString());
            await UserManager.AddLoginAsync(user.Id, login);

            // Now we should be able to find the user by that login info
            CassandraUser foundUser = await UserManager.FindAsync(login);
            foundUser.ShouldBeEquivalentToUser(user);
        }
    }
}