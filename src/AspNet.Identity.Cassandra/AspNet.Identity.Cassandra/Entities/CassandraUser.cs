using System;
using Microsoft.AspNet.Identity;

namespace AspNet.Identity.Cassandra.Entities
{
    public class CassandraUser : IUser
    {
        public string Id { get { return UserName; } }
        public string UserName { get; set; }

        public virtual string PasswordHash { get; set; }
        public virtual string SecurityStamp { get; set; }
        public bool IsLockoutEnabled { get; set; }
        public bool IsTwoFactorEnabled { get; set; }
        public string Email { get; set; }
        public int AccessFailedCount { get; set; }
        public DateTimeOffset? LockoutEndDate { get; set; }
        public string PhoneNumber { get; set; }
        public DateTimeOffset? PhoneNumberConfirmedOn { get; set; }
        public DateTimeOffset? EmailConfirmedOn { get; set; }

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
