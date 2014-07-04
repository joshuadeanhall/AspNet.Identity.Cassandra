using System;
using System.Security.Claims;

namespace AspNet.Identity.Cassandra.Entities
{
    public class CassandraUserClaim
    {
        public Claim Claim { get; set; }

        public CassandraUserClaim(Claim claim)
        {
            if (claim == null) throw new ArgumentNullException("claim");
            Claim = claim;
        }

        internal static string GenerateKey(string userId, string issuer, string type)
        {
            return string.Format(Constants.CassandraUserClaim, userId, issuer, type);
        }
    }
}