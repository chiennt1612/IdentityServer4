using IdentityServer.Constants;
using IdentityServer.Entities;
using IdentityServer.Interfaces;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;

namespace IdentityServer.DBContext
{
    public class AuditLogDbContext : DbContext, IAuditLoggingDbContext<AuditLog>
    {
        public AuditLogDbContext(DbContextOptions<AuditLogDbContext> dbContextOptions)
            : base(dbContextOptions)
        {

        }

        public Task<int> SaveChangesAsync()
        {
            return base.SaveChangesAsync();
        }

        public DbSet<AuditLog> AuditLog { get; set; }

        private void ConfigureLogContext(ModelBuilder builder)
        {
            builder.Entity<AuditLog>(log =>
            {
                log.ToTable(TableConsts.AuditLog);
                log.HasKey(x => x.Id);
            });
        }
    }
}
