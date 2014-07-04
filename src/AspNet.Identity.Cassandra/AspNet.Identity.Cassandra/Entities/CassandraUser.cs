using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cassandra.Data.Linq;
using Microsoft.AspNet.Identity;

namespace AspNet.Identity.Cassandra.Entities
{
    [Table("users")]
    public class CassandraUser : IUser
    {
        [ClusteringKey(0)]
        [Column("id")]
        public string Id { get; set; }
        [PartitionKey]
        [Column("username")]
        public string UserName { get; set; }
        [Column("passwordhash")]
        public virtual string PasswordHash { get; set; }
        [Column("securitystamp")]
        public virtual string SecurityStamp { get; set; }
        [Column("islockoutenabled")]
        public bool IsLockoutEnabled { get; set; }
        [Column("istwofactoryenabled")]
        public bool IsTwoFactorEnabled { get; set; }
        [Column("email")]
        public string Email { get; set; }
        [Column("accessfailedcount")]
        public int AccessFailedCount { get; set; }
        [Column("lockoutenddate")]
        public DateTimeOffset? LockoutEndDate { get; set; }
        [Column("phonenumber")]
        public string PhoneNumber { get; set; }
        [Column("phonenumberconfirmedon")]
        public DateTimeOffset? PhoneNumberConfirmedOn { get; set; }
        [Column("emailconfirmedon")]
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
