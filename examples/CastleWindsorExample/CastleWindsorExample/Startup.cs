using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(CastleWindsorExample.Startup))]
namespace CastleWindsorExample
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
