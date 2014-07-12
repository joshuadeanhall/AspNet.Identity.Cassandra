using System;
using Cassandra;
using Microsoft.AspNet.Identity;
using NUnit.Framework;

namespace AspNet.Identity.Cassandra.IntegrationTests
{
    /// <summary>
    /// Base class for integration test fixtures.  Does some common setup/teardown.
    /// </summary>
    public abstract class IntegrationTestBase
    {
        private const string TestKeyspaceFormat = "aspnet_identity_{0}";

        protected UserManager<CassandraUser, Guid> UserManager;
        private CassandraUserStore _userStore;
        private ISession _session;
        private string _keyspaceName;

        [TestFixtureSetUp]
        public virtual void TestSetup()
        {
            var cluster = Cluster.Builder()
                .AddContactPoint("127.0.0.1")
                .Build();
            _session = cluster.Connect();

            // Use a unique keyspace for each test fixture named after the test fixture's class name
            _keyspaceName = string.Format(TestKeyspaceFormat, GetType().Name.Replace(".", string.Empty));

            // Drop and re-create the keyspace
            _session.DeleteKeyspaceIfExists(_keyspaceName);
            _session.CreateKeyspaceIfNotExists(_keyspaceName);
            _session.ChangeKeyspace(_keyspaceName);

            _userStore = new CassandraUserStore(_session);

            // Exercise the UserManager class in tests since that's how consumers will use CassandarUserStore
            UserManager = new UserManager<CassandraUser, Guid>(_userStore);
        }

        [TestFixtureTearDown]
        public virtual void TestTearDown()
        {
            _session.DeleteKeyspaceIfExists(_keyspaceName);

            UserManager.Dispose();
            _userStore.Dispose();
            _session.Dispose();
        }
    }
}