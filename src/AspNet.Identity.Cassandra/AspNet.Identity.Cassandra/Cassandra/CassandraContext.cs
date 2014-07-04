using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cassandra;

namespace AspNet.Identity.Cassandra.Cassandra
{
    public class CassandraContext 
    {
        public ISession Session { get; set; }
        public CassandraContext()
        {
            var cluster = Cluster.Builder()
                .AddContactPoint("127.0.0.1")
                .Build();
            Session = cluster.Connect();
        }
    }
}
