using APIWithJWT.IdentityAuth;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace APIWithJWT.DbContext
{
    public static class SeedData
    {
        public static async Task Initialize(IServiceProvider serviceProvider)
        {
            using var scope = serviceProvider.CreateScope();
            var services = scope.ServiceProvider;

            var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();

            await EnsureRolesAsync(roleManager);
            await EnsureTestUserAsync(userManager);
        }

        private static async Task EnsureRolesAsync(RoleManager<IdentityRole> roleManager)
        {
            var roles = new[] { "User", "Admin" };

            foreach (var role in roles)
            {
                if (!await roleManager.RoleExistsAsync(role))
                {
                    await roleManager.CreateAsync(new IdentityRole(role));
                }
            }
        }

        private static async Task EnsureTestUserAsync(UserManager<ApplicationUser> userManager)
        {
            var testUser = new ApplicationUser { UserName = "test", Email = "test@example.com" };

            if (await userManager.FindByNameAsync(testUser.UserName) == null)
            {
                await userManager.CreateAsync(testUser, "Password123!");
                await userManager.AddToRoleAsync(testUser, "User");
            }
        }
    }
}
