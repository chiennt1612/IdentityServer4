// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer.DBContext;
using IdentityServer.Helpers;
using IdentityServer.Models;
using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Serilog;

namespace IdentityServer
{
    public class SeedData
    {
        public static void EnsureSeedData()
        {
            string connectionString = DecryptorProvider.Decrypt(Environment.GetEnvironmentVariable("CONNECTION_STRING"));
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(connectionString));
            services.AddIdentityServer()
                .AddConfigurationStore(options => {
                    options.ConfigureDbContext = b => b.UseSqlServer(connectionString);
                })
                .AddOperationalStore(options => {
                    options.ConfigureDbContext = b => b.UseSqlServer(connectionString);
                });

            services.AddIdentity<ApplicationUser, ApplicationRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddUserStore<ApplicationUserStore>()
                .AddRoleStore<ApplicationRoleStore>()
                .AddDefaultTokenProviders();

            using (var serviceProvider = services.BuildServiceProvider())
            {
                using (var scope = serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope())
                {
                    #region Migrate database
                    scope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.Migrate();
                    var context = scope.ServiceProvider.GetRequiredService<ConfigurationDbContext>(); context.Database.Migrate();
                    scope.ServiceProvider.GetRequiredService<ApplicationDbContext>().Database.Migrate();
                    #endregion

                    #region Seed data
                    #region Seed data ApplicationUser
                    var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
                    // Using a lambda expression.
                    for(var i = 2965; i < 1000000; i++)
                    {
                        if (i % 1000 == 0) Log.Debug($"i {i} {(i*100/1000000)}%");
                        var alice = userMgr.FindByNameAsync("alice" + i).Result;
                        if (alice == null)
                        {
                            alice = new ApplicationUser
                            {
                                UserName = "alice" + i,
                                Email = "AliceSmith"+i+"@email.com",
                                EmailConfirmed = true,
                            };
                            var result = userMgr.CreateAsync(alice, "Pass123$").Result;
                            if (!result.Succeeded)
                            {
                                throw new Exception(result.Errors.First().Description);
                            }

                            result = userMgr.AddClaimsAsync(alice, new Claim[]{
                            new Claim(JwtClaimTypes.Name, "Alice Smith" + i),
                            new Claim(JwtClaimTypes.GivenName, "Alice" + i),
                            new Claim(JwtClaimTypes.FamilyName, "Smith" + i),
                            new Claim(JwtClaimTypes.WebSite, "http://alice"+i+".com"),
                        }).Result;
                            if (!result.Succeeded)
                            {
                                throw new Exception(result.Errors.First().Description);
                            }
                            //Log.Debug("alice created");
                        }
                        else
                        {
                            Log.Debug("alice already exists");
                            var a = userMgr.AddClaimsAsync(alice, new Claim[]{
                            new Claim(JwtClaimTypes.Name, "Alice Smith" + i),
                            new Claim(JwtClaimTypes.GivenName, "Alice" + i),
                            new Claim(JwtClaimTypes.FamilyName, "Smith" + i),
                            new Claim(JwtClaimTypes.WebSite, "http://alice"+i+".com"),
                        }).Result;
                        }

                        var bob = userMgr.FindByNameAsync("bob" + i).Result;
                        if (bob == null)
                        {
                            bob = new ApplicationUser
                            {
                                UserName = "bob" + i,
                                Email = "BobSmith" + i + "@email.com",
                                EmailConfirmed = true
                            };
                            var result = userMgr.CreateAsync(bob, "Pass123$").Result;
                            if (!result.Succeeded)
                            {
                                throw new Exception(result.Errors.First().Description);
                            }

                            result = userMgr.AddClaimsAsync(bob, new Claim[]{
                            new Claim(JwtClaimTypes.Name, "Bob Smith" + i),
                            new Claim(JwtClaimTypes.GivenName, "Bob" + i),
                            new Claim(JwtClaimTypes.FamilyName, "Smith" + i),
                            new Claim(JwtClaimTypes.WebSite, "http://bob"+i+".com"),
                            new Claim("location", "somewhere")
                        }).Result;
                            if (!result.Succeeded)
                            {
                                throw new Exception(result.Errors.First().Description);
                            }
                            //Log.Debug("bob created");
                        }
                        else
                        {
                            Log.Debug("bob already exists");
                        }

                    };                    
                    #endregion
                    
                    #region Seed data ConfigurationDbContext
                    if (!context.Clients.Any())
                    {
                        foreach (var client in Config.Clients)
                        {
                            context.Clients.Add(client.ToEntity());
                        }
                        context.SaveChanges();
                    }

                    if (!context.IdentityResources.Any())
                    {
                        foreach (var resource in Config.IdentityResources)
                        {
                            context.IdentityResources.Add(resource.ToEntity());
                        }
                        context.SaveChanges();
                    }

                    if (!context.ApiScopes.Any())
                    {
                        foreach (var resource in Config.ApiScopes)
                        {
                            context.ApiScopes.Add(resource.ToEntity());
                        }
                        context.SaveChanges();
                    }
                    #endregion
                    #endregion

                }
            }
        }
    }
}
