using System;
using System.Security.Claims;

namespace AspNet.Identity.Cassandra.Entities
{
    public class CassandraUserClaim
    {
        public string UserId { get; set; }
        public string Issuer { get; set; }
        public string OriginalIssuer { get; set; }
        public string Type { get; set; }
        public string Value { get; set; }
        public string ValueType { get; set; }
        
        public CassandraUserClaim(Claim claim)
        {
            if (claim == null) throw new ArgumentNullException("claim");
            Issuer = claim.Issuer;
            OriginalIssuer = claim.OriginalIssuer;
            Type = claim.Type;
            Value = claim.Value;
            ValueType = claim.ValueType;
        }
    }
}