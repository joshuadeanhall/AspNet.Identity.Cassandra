using Microsoft.AspNet.Identity;

namespace AspNet.Identity.Cassandra.Entities
{
    public class CassandraUserLogin
    {
        public string UserId { get; set; }
        public string LoginProvider { get; set; }
        public string ProviderKey { get; set; }

        public CassandraUserLogin(string userId, UserLoginInfo loginInfo)
        {
            UserId = userId;
            LoginProvider = loginInfo.LoginProvider;
            ProviderKey = loginInfo.ProviderKey;
        }
    }
}