using System;
using System.Security.Claims;
using Cassandra.Data.Linq;

namespace AspNet.Identity.Cassandra.Entities
{
    [Table("claims")]
    public class CassandraUserClaim
    {
        [Column("id")]
        public string ClaimId { get; set; }
        [Column("userid")]
        [ClusteringKey(0)]
        public string UserId { get; set; }
        [Column("issuer")]
        public string Issuer { get; set; }
        [Column("originalissuer")]
        public string OriginalIssuer { get; set; }
        [Column("type")]
        [PartitionKey(1)]
        public string Type { get; set; }
        [Column("value")]
        [PartitionKey(0)]
        public string Value { get; set; }
        [Column("valuetype")]
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

        internal static string GenerateKey(string userId, string issuer, string type)
        {
            return string.Format(Constants.CassandraUserClaim, userId, issuer, type);
        }
    }
}