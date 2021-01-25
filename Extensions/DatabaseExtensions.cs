using System;
using System.Reflection;
using IdentityServer.Entities;
using IdentityServer.Helpers;
using IdentityServer.Interfaces;
using IdentityServer4.EntityFramework.Storage;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityServer.Extensions
{
    public static class DatabaseExtensions
    {
        #region helper
        public static void RegisterDbContexts<TIdentityDbContext, TDataProtectionDbContext, TLogDbContext, TAuditLoggingDbContext>
                (this IServiceCollection services, IConfiguration configuration)
            where TIdentityDbContext : DbContext
            where TDataProtectionDbContext : DbContext
            where TLogDbContext : DbContext, ILogDbContext
            where TAuditLoggingDbContext : DbContext, IAuditLoggingDbContext<AuditLog>
        {
            //string connectionString = configuration.GetConnectionString("DefaultConnection");
            string connectionString = DecryptorProvider.Decrypt(Environment.GetEnvironmentVariable("CONNECTION_STRING"));

            services.RegisterSqlServerDbContexts<TIdentityDbContext, TDataProtectionDbContext, TLogDbContext, TAuditLoggingDbContext>
                (connectionString, connectionString, connectionString, connectionString, connectionString, connectionString);
        }

        public static void AddIdSHealthChecks<TConfigurationDbContext, TPersistedGrantDbContext, TIdentityDbContext, TDataProtectionDbContext>
            (this IServiceCollection services, IConfiguration configuration)
            where TConfigurationDbContext : DbContext
            where TPersistedGrantDbContext : DbContext
            where TIdentityDbContext : DbContext
            where TDataProtectionDbContext : DbContext, IDataProtectionKeyContext
        {
            //string connectionString = configuration.GetConnectionString("DefaultConnection");
            string connectionString = DecryptorProvider.Decrypt(Environment.GetEnvironmentVariable("CONNECTION_STRING"));

            services.AddIdSHealthChecks<TConfigurationDbContext, TPersistedGrantDbContext, TIdentityDbContext, TDataProtectionDbContext>
                (connectionString, connectionString, connectionString, connectionString);
        }

        public static void RegisterSqlServerDbContexts<TIdentityDbContext, TDataProtectionDbContext, TLogDbContext, TAuditLoggingDbContext>
            (this IServiceCollection services,
            string identityConnectionString, string configurationConnectionString,
            string persistedGrantConnectionString, string dataProtectionConnectionString,
            string errorLoggingConnectionString, string auditLoggingConnectionString)
            where TIdentityDbContext : DbContext
            where TDataProtectionDbContext : DbContext
            where TLogDbContext : DbContext, ILogDbContext
            where TAuditLoggingDbContext : DbContext, IAuditLoggingDbContext<AuditLog>
        {
            var migrationsAssembly = typeof(DatabaseExtensions).GetTypeInfo().Assembly.GetName().Name;

            // Config DB for identity
            services.AddDbContext<TIdentityDbContext>(options => options.UseSqlServer(identityConnectionString, sql => sql.MigrationsAssembly(migrationsAssembly)));

            // Config DB from existing connection
            services.AddConfigurationDbContext(options =>
            {
                options.ConfigureDbContext = b => b.UseSqlServer(configurationConnectionString,
                    sql => sql.MigrationsAssembly(migrationsAssembly));
            });

            // Operational DB from existing connection
            services.AddOperationalDbContext(options =>
            {
                options.ConfigureDbContext = b => b.UseSqlServer(persistedGrantConnectionString,
                    sql => sql.MigrationsAssembly(migrationsAssembly));
            });

            // Log DB from existing connection
            services.AddDbContext<TLogDbContext>(options => options.UseSqlServer(errorLoggingConnectionString, sql => sql.MigrationsAssembly(migrationsAssembly)));

            // Audit logging connection
            services.AddDbContext<TAuditLoggingDbContext>(options => options.UseSqlServer(auditLoggingConnectionString, sql => sql.MigrationsAssembly(migrationsAssembly)));

            // DataProtectionKey DB from existing connection
            services.AddDbContext<TDataProtectionDbContext>(options => options.UseSqlServer(dataProtectionConnectionString, sql => sql.MigrationsAssembly(migrationsAssembly)));
        }
        #endregion
    }
}
