using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(CassandraAuthSimpleExample.Startup))]
namespace CassandraAuthSimpleExample
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
