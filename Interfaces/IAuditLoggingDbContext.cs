using IdentityServer.Entities;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;

namespace IdentityServer.Interfaces
{
    public interface IAuditLoggingDbContext<TAuditLog> where TAuditLog : AuditLog
    {
        DbSet<TAuditLog> AuditLog { get; set; }

        Task<int> SaveChangesAsync();
    }
}
