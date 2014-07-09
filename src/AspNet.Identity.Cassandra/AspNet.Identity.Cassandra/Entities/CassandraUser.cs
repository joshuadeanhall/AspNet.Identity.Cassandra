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
    }
}
