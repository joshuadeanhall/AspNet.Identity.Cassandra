using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AspNet.Identity.Cassandra.Entities;
using Cassandra;
using Cassandra.Data.Linq;

namespace AspNet.Identity.Cassandra.Cassandra
{
    public class UserContext : Context
    {
        public UserContext(Session session) : base(session)
        {
            AddTable<CassandraUser>();
            CreateTablesIfNotExist();

            //Table<CassandraUser> table = session.GetTable<CassandraUser>();
            //table.CreateIfNotExists();
        }
    }
}
