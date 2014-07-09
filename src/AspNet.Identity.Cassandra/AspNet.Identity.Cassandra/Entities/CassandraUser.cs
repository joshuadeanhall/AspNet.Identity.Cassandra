using System;
using Microsoft.AspNet.Identity;

namespace AspNet.Identity.Cassandra.Entities
{
    public class CassandraUser : IUser<Guid>
    {
        public Guid Id { get; internal set; }
        public string UserName { get; set; }
    }
}
