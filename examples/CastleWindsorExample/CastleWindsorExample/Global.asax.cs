using System.Collections.Generic;
using System.Linq;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using System.Web.SessionState;
using AspNet.Identity.Cassandra.Entities;
using AspNet.Identity.Cassandra.Store;
using Cassandra;
using Castle.MicroKernel.Registration;
using Castle.Windsor;
using Microsoft.AspNet.Identity;

namespace CastleWindsorExample
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
            IWindsorContainer container = new WindsorContainer();
            container.Register(Component.For<UserManager<CassandraUser>>().LifestylePerWebRequest());
            container.Register(
                Component.For<IUserStore<CassandraUser>>().ImplementedBy<CassandraUserStore<CassandraUser>>().LifestylePerWebRequest());

            container.Register(
                Component.For<Cluster>()
                    .UsingFactoryMethod(k => Cluster.Builder().AddContactPoint("127.0.0.1").Build())
                    .LifestylePerWebRequest(),

                Component.For<ISession>().UsingFactoryMethod(k => k.Resolve<Cluster>().Connect("windsorexample")).LifestylePerWebRequest()
            );

            container.Register(
                Classes.FromThisAssembly().BasedOn<IController>().LifestyleTransient()
            );

            ControllerBuilder.Current.SetControllerFactory(new WindsorControllerFactory(container.Kernel));
        }
    }
}
