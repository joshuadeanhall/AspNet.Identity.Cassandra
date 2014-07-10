using System;
using System.Security.Claims;
using Cassandra;
using Microsoft.AspNet.Identity;
using NUnit.Framework;

namespace AspNet.Identity.Cassandra.IntegrationTests
{
    [TestFixture]
    public class CassandraUserStoreTest
    {
        private ISession _session;
        private CassandraUserStore<CassandraUser> userStore;
            [TestFixtureSetUp]
        public void TestSetup()
        {
            var cluster = Cluster.Builder()
                .AddContactPoint("127.0.0.1")
                .Build();
            _session = cluster.Connect();
            _session.CreateKeyspaceIfNotExists("simpleexample");
            _session.ChangeKeyspace("simpleexample");

            userStore = new CassandraUserStore<CassandraUser>(_session);
        }

        [TestFixtureTearDown]
        public void TestTearDown()
        {
            _session.DeleteKeyspaceIfExists("simpleexample");
            _session.Dispose();
        }

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
            await userStore.CreateAsync(user);
            var savedUser = await userStore.FindByIdAsync(user.Id);
            Assert.AreEqual(user.Id, savedUser.Id);
            savedUser.Email = "newEmail@test.com";
            await userStore.UpdateAsync(savedUser);
            var updatedUser = await userStore.FindByIdAsync(user.Id);
            Assert.AreEqual(savedUser.Email, updatedUser.Email);
            await userStore.DeleteAsync(savedUser);
            var noUser = await userStore.FindByIdAsync(user.Id);
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

            await userStore.CreateAsync(user);
            await userStore.CreateAsync(user2);
            var userById = await userStore.FindByIdAsync(user.Id);
            var userByName = await userStore.FindByNameAsync(user.UserName);
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

            await userStore.CreateAsync(user);
            await userStore.CreateAsync(user2);
            var loginInfo = new UserLoginInfo("testProvider", "providerKey");
            var loginInfo2 = new UserLoginInfo("testLoginProvider2", "providerKey2");
            var loginInfo3 = new UserLoginInfo("testProv3", "prov3");
            await userStore.AddLoginAsync(user, loginInfo);
            await userStore.AddLoginAsync(user, loginInfo2);
            await userStore.AddLoginAsync(user2, loginInfo3);
            var logins = await userStore.GetLoginsAsync(user);
            Assert.AreEqual(2, logins.Count);
            var findUser = await userStore.FindAsync(loginInfo);
            Assert.AreEqual(user.Id, findUser.Id);
            await userStore.RemoveLoginAsync(user, loginInfo);
            var removedLogins = await userStore.GetLoginsAsync(user);
            Assert.AreEqual(1, removedLogins.Count);
            await userStore.RemoveLoginAsync(user, loginInfo2);
            var noLogins = await userStore.GetLoginsAsync(user);
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
            await userStore.AddClaimAsync(user, claim1);
            await userStore.AddClaimAsync(user, claim2);
            await userStore.AddClaimAsync(user2, claim3);
            var allClaims = await userStore.GetClaimsAsync(user);
            Assert.AreEqual(2, allClaims.Count);
            await userStore.RemoveClaimAsync(user, claim2);
            var afterDeleteClaims = await userStore.GetClaimsAsync(user);
            Assert.AreEqual(1, afterDeleteClaims.Count);
            await userStore.RemoveClaimAsync(user, claim1);
            var noClaims = await userStore.GetClaimsAsync(user);
            Assert.AreEqual(0, noClaims.Count);
            DeleteUser(user);
            DeleteUser(user2);

        }

        private async void DeleteUser(CassandraUser user)
        {
            await userStore.DeleteAsync(user);
        }
    }
}
