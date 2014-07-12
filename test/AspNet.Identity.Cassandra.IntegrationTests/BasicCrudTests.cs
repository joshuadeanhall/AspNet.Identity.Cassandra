using System;
using FluentAssertions;
using Microsoft.AspNet.Identity;
using NUnit.Framework;

namespace AspNet.Identity.Cassandra.IntegrationTests
{
    /// <summary>
    /// Tests for basic user CRUD.
    /// </summary>
    [TestFixture]
    public class BasicCrudTests : IntegrationTestBase
    {
        [Test]
        public async void CreateUser()
        {
            // Create user
            var originalUser = new CassandraUser(Guid.NewGuid()) { UserName = "testUser1" };
            IdentityResult result = await UserManager.CreateAsync(originalUser);
            result.ShouldBeSuccess();

            // Try to find users by id and username
            CassandraUser foundUser = await UserManager.FindByIdAsync(originalUser.Id);
            foundUser.ShouldBeEquivalentToUser(originalUser);

            foundUser = await UserManager.FindByNameAsync(originalUser.UserName);
            foundUser.ShouldBeEquivalentToUser(originalUser);
        }

        [Test]
        public async void ChangeUsername()
        {
            // Create user, then lookup by Id
            var originalUser = new CassandraUser(Guid.NewGuid()) { UserName = "originalUserName" };
            await UserManager.CreateAsync(originalUser);
            CassandraUser foundUser = await UserManager.FindByIdAsync(originalUser.Id);
            
            // Change the username and update
            const string newUserName = "testUser2";
            foundUser.UserName = newUserName;
            IdentityResult result = await UserManager.UpdateAsync(foundUser);
            result.ShouldBeSuccess();

            // Should not be able to find them by the old username
            foundUser = await UserManager.FindByNameAsync(originalUser.UserName);
            foundUser.Should().BeNull();

            // Should still be able to find by id and new username
            foundUser = await UserManager.FindByIdAsync(originalUser.Id);
            foundUser.Should().NotBeNull();
            foundUser.UserName.Should().Be(newUserName);

            foundUser = await UserManager.FindByNameAsync(newUserName);
            foundUser.Should().NotBeNull();
            foundUser.Id.Should().Be(originalUser.Id);
        }

        [Test]
        public async void DeleteUser()
        {
            // Create user, then lookup by Id
            var originalUser = new CassandraUser(Guid.NewGuid()) { UserName = "deletedUser" };
            await UserManager.CreateAsync(originalUser);
            CassandraUser foundUser = await UserManager.FindByIdAsync(originalUser.Id);
            
            // Delete the user
            IdentityResult result = await UserManager.DeleteAsync(foundUser);
            result.ShouldBeSuccess();

            // Should not be able to find by id or username
            foundUser = await UserManager.FindByIdAsync(originalUser.Id);
            foundUser.Should().BeNull();

            foundUser = await UserManager.FindByNameAsync(originalUser.UserName);
            foundUser.Should().BeNull();
        }
    }
}
