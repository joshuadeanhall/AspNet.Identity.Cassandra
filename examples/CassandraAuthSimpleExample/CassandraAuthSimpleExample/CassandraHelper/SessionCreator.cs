using Cassandra;

namespace CassandraAuthSimpleExample.CassandraHelper
{
    public class SessionCreator
    {
        public static ISession Create()
        {
            var cluster = Cluster.Builder()
                .AddContactPoint("127.0.0.1")
                .Build();
            var session = cluster.Connect();
            session.CreateKeyspaceIfNotExists("simpleexample");
            session.ChangeKeyspace("simpleexample");
            return session;
        }
    }
}