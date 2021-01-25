using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using IdentityServer.Models;
using Microsoft.AspNetCore.Identity;
using IdentityServer.Constants;

namespace IdentityServer.DBContext
{
    //IdentityDbContext<TUser, TRole, TKey> : IdentityDbContext<TUser, TRole, TKey, IdentityUserClaim<TKey>, IdentityUserRole<TKey>, IdentityUserLogin<TKey>, IdentityRoleClaim<TKey>, IdentityUserToken<TKey>>
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, long, ApplicationUserClaim, ApplicationUserRole, ApplicationUserLogin, ApplicationUserRoleClaim, ApplicationUserToken>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        private void ConfigureIdentityContext(ModelBuilder builder)
        {
            builder.Entity<ApplicationRole>().ToTable(TableConsts.IdentityRoles);
            builder.Entity<ApplicationUserRoleClaim>().ToTable(TableConsts.IdentityRoleClaims);
            builder.Entity<ApplicationUserRole>().ToTable(TableConsts.IdentityUserRoles);

            builder.Entity<ApplicationUser>(a =>
            {
                a.ToTable(TableConsts.IdentityUsers);
                a.HasKey(x => x.Id);
                a.HasIndex(u => u.PhoneNumber).IsUnique();
                a.HasIndex(u => u.Email).IsUnique();
                a.HasIndex(u => u.UserName).IsUnique();
            });
            builder.Entity<ApplicationUserLogin>().ToTable(TableConsts.IdentityUserLogins);
            builder.Entity<ApplicationUserClaim>().ToTable(TableConsts.IdentityUserClaims);
            builder.Entity<ApplicationUserToken>().ToTable(TableConsts.IdentityUserTokens);
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            // Customize the ASP.NET Identity model and override the defaults if needed.
            // For example, you can rename the ASP.NET Identity table names and more.
            // Add your customizations after calling base.OnModelCreating(builder);
            ConfigureIdentityContext(builder);
        }
    }

    public class ApplicationUserStore : UserStore<ApplicationUser, ApplicationRole, ApplicationDbContext, long, ApplicationUserClaim, ApplicationUserRole, ApplicationUserLogin, ApplicationUserToken, ApplicationUserRoleClaim>
    {
        public ApplicationUserStore(ApplicationDbContext context, IdentityErrorDescriber describer = null)
            : base(context, describer)
        {
        }
    }

    public class ApplicationRoleStore : RoleStore<ApplicationRole, ApplicationDbContext, long>
    {
        public ApplicationRoleStore(ApplicationDbContext context, IdentityErrorDescriber describer = null)
            : base(context, describer)
        {
        }
    }
}
