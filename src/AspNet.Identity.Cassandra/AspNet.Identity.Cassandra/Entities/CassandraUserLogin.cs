using Cassandra.Data.Linq;
using Microsoft.AspNet.Identity;

namespace AspNet.Identity.Cassandra.Entities
{
    [Table("logins")]
    public class CassandraUserLogin
    {
        [Column("id")]
        public string Id { get; set; }
        [Column("userid")]
        [PartitionKey(0)]
        public string UserId { get; set; }
        [Column("loginprovider")]
        [ClusteringKey(0)]
        public string LoginProvider { get; set; }
        [Column("providerkey")]
        [ClusteringKey(1)]
        public string ProviderKey { get; set; }

        public CassandraUserLogin(string userId, UserLoginInfo loginInfo)
        {
            UserId = userId;
            Id = GenerateKey(loginInfo.LoginProvider, loginInfo.ProviderKey);
            LoginProvider = loginInfo.LoginProvider;
            ProviderKey = loginInfo.ProviderKey;
        }

        internal static string GenerateKey(string loginProvider, string providerKey)
        {
            return string.Format(Constants.CassandraUserLoginKeyTemplate, loginProvider, providerKey);
        }
    }
}