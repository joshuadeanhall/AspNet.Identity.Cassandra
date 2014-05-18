using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;

namespace AspNet.Identity.Cassandra.Entities
{
    public class CassandraUser : IUser
    {
        public string Id { get; private set; }
        public string UserName { get; set; }
        private ICollection<CassandraUserClaim> _claims { get; set; }
        private ICollection<CassandraUserLogin> _logins { get; set; }
        public virtual string PasswordHash { get; set; }
        private ICollection<CassandraUserRole> _roles { get; set; }
        public virtual string SecurityStamp { get; set; }

        public CassandraUser()
        {
        }

        public CassandraUser(string userName)
        {
            if (userName == null) throw new ArgumentNullException("userName");
            UserName = userName;
        }
        public virtual void SetPasswordHash(string passwordHash)
        {
            PasswordHash = passwordHash;
        }
        public virtual void SetSecurityStamp(string securityStamp)
        {
            SecurityStamp = securityStamp;
        }
    }
}
