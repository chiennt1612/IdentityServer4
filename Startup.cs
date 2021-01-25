// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer.DBContext;
using IdentityServer.Models;
using IdentityServer.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Reflection;
using IdentityServer.Extensions;
using IdentityServer.Helpers;
using System.IO;
using dotenv.net;

namespace IdentityServer
{
    public class Startup
    {
        public IWebHostEnvironment Environment { get; }
        public IConfiguration Configuration { get; }

        public Startup(IWebHostEnvironment environment, IConfiguration configuration)
        {
            var envFilePath = $".env";
            if (File.Exists(envFilePath))
            {
                DotEnv.Config(true, envFilePath);
            }
            else
            {
                DotEnv.AutoConfig();
            }
            Environment = environment;
            Configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            //string connectionString = Configuration.GetConnectionString("DefaultConnection");
            //string connectionString = DecryptorProvider.Decrypt(Environment.GetEnvironmentVariable("CONNECTION_STRING"));
            var migrationsAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;

            var adminUseCors = Configuration.GetSection(nameof(UseCors)).Get<UseCors>();
            if (adminUseCors == null)
            {
                adminUseCors = new UseCors() { CorsAllowAnyOrigin  = true};
            }
            services.AddControllersWithViews();

            //services.AddTransient<IEmailSender, EmailSender>();
            //services.AddTransient<ISmsSender, AuthMessageSender>();
            //services.Configure<SMSoptions>(Configuration);
            services.AddSenders(Configuration);

            // Register DbContexts for IdentityServer and Identity
            RegisterDbContexts(services);

            RegisterAuthentication(services);

            // Add authorization policies for MVC
            services.AddAuthorizationPolicies();

            //services.AddIdSHealthChecks<ConfigurationDbContext, PersistedGrantDbContext, ApplicationDbContext, DataProtectionDbContext>(Configuration);

            services.AddAdminApiCors(adminUseCors);
        }

        public void Configure(IApplicationBuilder app)
        {
            if (Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }

            app.UseStaticFiles();

            app.UseRouting();
            app.UseIdentityServer();
            app.UseAuthorization();
            app.UseCors();
            //app.Use(async (context, next) =>
            //{
            //    if (!context.User.Identity.IsAuthenticated)
            //    {
            //        context.Response.Redirect("/Account/Login");
            //    }
            //    else
            //    {
            //        await next.Invoke();
            //    }
            //});
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }

        #region helper
        public virtual void RegisterDbContexts(IServiceCollection services)
        {
            services.RegisterDbContexts<ApplicationDbContext, DataProtectionDbContext, LogDbContext, AuditLogDbContext>(Configuration);
        }

        public virtual void RegisterAuthentication(IServiceCollection services)
        {
            services.AddAuthenticationServices<ApplicationDbContext, ApplicationUser, ApplicationRole>(Configuration);
            services.AddIdentityServer<ConfigurationDbContext, PersistedGrantDbContext, ApplicationUser>(Configuration);
            services.AddExternalIdentityServices(Configuration);
        }
        #endregion
    }
}