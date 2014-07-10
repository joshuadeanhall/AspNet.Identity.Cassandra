using System;
using Microsoft.AspNet.Identity;

namespace AspNet.Identity.Cassandra.Entities
{
    /// <summary>
    /// Represents a user.
    /// </summary>
    public class CassandraUser : IUser<Guid>
    {
        /// <summary>
        /// The unique Id of the user.
        /// </summary>
        public Guid Id { get; internal set; }

        /// <summary>
        /// The user's username.
        /// </summary>
        public string UserName { get; set; }

        /// <summary>
        /// The password hash for the user.
        /// </summary>
        internal string PasswordHash { get; set; }

        /// <summary>
        /// The security stamp for the user.
        /// </summary>
        internal string SecurityStamp { get; set; }

        /// <summary>
        /// Whether or not two factor authentication is enabled for the user.
        /// </summary>
        internal bool IsTwoFactorEnabled { get; set; }

        /// <summary>
        /// The number of times the user has tried and failed to login.
        /// </summary>
        internal int AccessFailedCount { get; set; }

        /// <summary>
        /// Whether or not lockout is enabled for the user.
        /// </summary>
        internal bool IsLockoutEnabled { get; set; }

        /// <summary>
        /// When the user's lockout period will end.
        /// </summary>
        internal DateTimeOffset LockoutEndDate { get; set; }

    }
}
