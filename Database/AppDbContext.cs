using Microsoft.EntityFrameworkCore; // for Dbcontext
using Authenticator2.Models;


namespace Authenticator2.Database
{
    public class AppDbContext : DbContext
    {
        public DbSet<LoginRequest> Users { get; set; }

        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configure User table
            modelBuilder.Entity<LoginRequest>(entity =>
            {
                entity.HasKey(e => e.Id); // Primary Key
                entity.Property(e => e.Username).IsRequired().HasMaxLength(100);
                entity.Property(e => e.Password).IsRequired();
                entity.Property(e => e.SecretKey).HasMaxLength(256);
            });
        }
    }
}
