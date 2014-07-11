using System;
using Cassandra;
using FluentAssertions;
using Microsoft.AspNet.Identity;
using NUnit.Framework;

namespace AspNet.Identity.Cassandra.IntegrationTests
{
    [TestFixture]
    public class CassandraUserStoreTest
    {
        private ISession _session;
        private UserManager<CassandraUser, Guid> _manager;

        private const string TestKeyspace = "aspnet_identity_integrationtest";

        [TestFixtureSetUp]
        public void TestSetup()
        {
            var cluster = Cluster.Builder()
                .AddContactPoint("127.0.0.1")
                .Build();
            _session = cluster.Connect();

            // Drop and re-create the keyspace
            _session.DeleteKeyspaceIfExists(TestKeyspace);
            _session.CreateKeyspaceIfNotExists(TestKeyspace);
            _session.ChangeKeyspace(TestKeyspace);

            var userStore = new CassandraUserStore(_session);

            // Exercise the UserManager class in tests since that's how consumers will use CassandarUserStore
            _manager = new UserManager<CassandraUser, Guid>(userStore);
        }

        [TestFixtureTearDown]
        public void TestTearDown()
        {
            _manager.Dispose();
            _session.Dispose();
        }

        [Test]
        public async void BasicCrud()
        {
            // Create user
            var originalUser = new CassandraUser(Guid.NewGuid()) {UserName = "testUser1"};
            IdentityResult result = await _manager.CreateAsync(originalUser);
            result.Succeeded.Should().BeTrue();
            
            // Try to find users by id and username
            CassandraUser foundUser = await _manager.FindByIdAsync(originalUser.Id);
            foundUser.Should().NotBeNull();
            foundUser.UserName.Should().Be(originalUser.UserName);

            foundUser = await _manager.FindByNameAsync(originalUser.UserName);
            foundUser.Should().NotBeNull();
            foundUser.Id.Should().Be(originalUser.Id);

            // Change the username and update
            const string newUserName = "testUser2";
            foundUser.UserName = newUserName;
            result = await _manager.UpdateAsync(foundUser);
            result.Succeeded.Should().BeTrue();

            // Should not be able to find them by the old username
            foundUser = await _manager.FindByNameAsync(originalUser.UserName);
            foundUser.Should().BeNull();

            // Should still be able to find by id and new username
            foundUser = await _manager.FindByIdAsync(originalUser.Id);
            foundUser.Should().NotBeNull();
            foundUser.UserName.Should().Be(newUserName);
            
            foundUser = await _manager.FindByNameAsync(newUserName);
            foundUser.Should().NotBeNull();
            foundUser.Id.Should().Be(originalUser.Id);
            
            // Delete the user
            result = await _manager.DeleteAsync(foundUser);
            result.Succeeded.Should().BeTrue();

            // Should not be able to find by id or username
            foundUser = await _manager.FindByIdAsync(originalUser.Id);
            foundUser.Should().BeNull();

            foundUser = await _manager.FindByNameAsync(newUserName);
            foundUser.Should().BeNull();
        }

        /*
        [Test]
        public async void CRUDUser()
        {
            var user = new CassandraUser
            {
                AccessFailedCount = 0,
                Email = "test@test.com",
                EmailConfirmedOn = DateTime.Now,
                IsLockoutEnabled = false,
                IsTwoFactorEnabled = false,
                PasswordHash = "Phas",
                PhoneNumber = "Phone",
                PhoneNumberConfirmedOn = DateTime.Now,
                UserName = "testUser"
            };
            await _userStore.CreateAsync(user);
            var savedUser = await _userStore.FindByIdAsync(user.Id);
            Assert.AreEqual(user.Id, savedUser.Id);
            savedUser.Email = "newEmail@test.com";
            await _userStore.UpdateAsync(savedUser);
            var updatedUser = await _userStore.FindByIdAsync(user.Id);
            Assert.AreEqual(savedUser.Email, updatedUser.Email);
            await _userStore.DeleteAsync(savedUser);
            var noUser = await _userStore.FindByIdAsync(user.Id);
            Assert.IsNull(noUser.Id);
            DeleteUser(user);
        }

        [Test]
        public async void FindUserMethods()
        {
            var user = new CassandraUser
            {
                AccessFailedCount = 0,
                Email = "test@test.com",
                EmailConfirmedOn = DateTime.Now,
                IsLockoutEnabled = false,
                IsTwoFactorEnabled = false,
                PasswordHash = "Phas",
                PhoneNumber = "Phone",
                PhoneNumberConfirmedOn = DateTime.Now,
                UserName = "testUser"
            };

            var user2 = new CassandraUser
            {
                AccessFailedCount = 0,
                Email = "test2@test.com",
                EmailConfirmedOn = DateTime.Now,
                IsLockoutEnabled = false,
                IsTwoFactorEnabled = false,
                PasswordHash = "Phas2",
                PhoneNumber = "Phone2",
                PhoneNumberConfirmedOn = DateTime.Now,
                UserName = "testUser2"
            };

            await _userStore.CreateAsync(user);
            await _userStore.CreateAsync(user2);
            var userById = await _userStore.FindByIdAsync(user.Id);
            var userByName = await _userStore.FindByNameAsync(user.UserName);
            //var userByEmail = await userStore.FindByEmailAsync(user.Email);

            Assert.AreEqual(user.Id, userById.Id);
            Assert.AreEqual(user.Id, userByName.Id);
            //Assert.AreEqual(user.Id, userByEmail.Id);
            DeleteUser(user);
            DeleteUser(user2);
        }

        [Test]
        public async void LoginCRUD()
        {
            var user = new CassandraUser
            {
                AccessFailedCount = 0,
                Email = "test@test.com",
                EmailConfirmedOn = DateTime.Now,
                IsLockoutEnabled = false,
                IsTwoFactorEnabled = false,
                PasswordHash = "Phas",
                PhoneNumber = "Phone",
                PhoneNumberConfirmedOn = DateTime.Now,
                UserName = "testUser"
            };

            var user2 = new CassandraUser
            {
                AccessFailedCount = 0,
                Email = "test2@test.com",
                EmailConfirmedOn = DateTime.Now,
                IsLockoutEnabled = false,
                IsTwoFactorEnabled = false,
                PasswordHash = "Phas2",
                PhoneNumber = "Phone2",
                PhoneNumberConfirmedOn = DateTime.Now,
                UserName = "testUser2"
            };

            await _userStore.CreateAsync(user);
            await _userStore.CreateAsync(user2);
            var loginInfo = new UserLoginInfo("testProvider", "providerKey");
            var loginInfo2 = new UserLoginInfo("testLoginProvider2", "providerKey2");
            var loginInfo3 = new UserLoginInfo("testProv3", "prov3");
            await _userStore.AddLoginAsync(user, loginInfo);
            await _userStore.AddLoginAsync(user, loginInfo2);
            await _userStore.AddLoginAsync(user2, loginInfo3);
            var logins = await _userStore.GetLoginsAsync(user);
            Assert.AreEqual(2, logins.Count);
            var findUser = await _userStore.FindAsync(loginInfo);
            Assert.AreEqual(user.Id, findUser.Id);
            await _userStore.RemoveLoginAsync(user, loginInfo);
            var removedLogins = await _userStore.GetLoginsAsync(user);
            Assert.AreEqual(1, removedLogins.Count);
            await _userStore.RemoveLoginAsync(user, loginInfo2);
            var noLogins = await _userStore.GetLoginsAsync(user);
            Assert.AreEqual(0, noLogins.Count);
            DeleteUser(user);
            DeleteUser(user2);
        }

        [Test]
        public async void ClaimsOperations()
        {
            var user = new CassandraUser
            {
                AccessFailedCount = 0,
                Email = "test@test.com",
                EmailConfirmedOn = DateTime.Now,
                IsLockoutEnabled = false,
                IsTwoFactorEnabled = false,
                PasswordHash = "Phas",
                PhoneNumber = "Phone",
                PhoneNumberConfirmedOn = DateTime.Now,
                UserName = "testUser"
            };

            var user2 = new CassandraUser
            {
                AccessFailedCount = 0,
                Email = "test2@test.com",
                EmailConfirmedOn = DateTime.Now,
                IsLockoutEnabled = false,
                IsTwoFactorEnabled = false,
                PasswordHash = "Phas2",
                PhoneNumber = "Phone2",
                PhoneNumberConfirmedOn = DateTime.Now,
                UserName = "testUser2"
            };

            var claim1 = new Claim("claim1type", "1");
            var claim2 = new Claim("type2", "2");
            var claim3 = new Claim("type3", "3");
            await _userStore.AddClaimAsync(user, claim1);
            await _userStore.AddClaimAsync(user, claim2);
            await _userStore.AddClaimAsync(user2, claim3);
            var allClaims = await _userStore.GetClaimsAsync(user);
            Assert.AreEqual(2, allClaims.Count);
            await _userStore.RemoveClaimAsync(user, claim2);
            var afterDeleteClaims = await _userStore.GetClaimsAsync(user);
            Assert.AreEqual(1, afterDeleteClaims.Count);
            await _userStore.RemoveClaimAsync(user, claim1);
            var noClaims = await _userStore.GetClaimsAsync(user);
            Assert.AreEqual(0, noClaims.Count);
            DeleteUser(user);
            DeleteUser(user2);

        }

        private async void DeleteUser(CassandraUser user)
        {
            await _userStore.DeleteAsync(user);
        }
         * */
    }
}
