using Microsoft.AspNet.Identity;

namespace AspNet.Identity.Cassandra.Entities
{
    public class CassandraUserLogin
    {
        public string Id { get; set; }
        public string UserId { get; set; }
        public UserLoginInfo LoginInfo { get; set; }

        public CassandraUserLogin(string userId, UserLoginInfo loginInfo)
        {
            UserId = userId;
            Id = GenerateKey(loginInfo.LoginProvider, loginInfo.ProviderKey);
            LoginInfo = loginInfo;
        }

        

        internal static string GenerateKey(string loginProvider, string providerKey)
        {
            return string.Format(Constants.CassandraUserLoginKeyTemplate, loginProvider, providerKey);
        }
    }
}