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


            var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();

            await CreateRolesAndUsers(userManager, roleManager);
        }

        private static async Task CreateRolesAndUsers(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            string[] roleNames = { "Admin", "Waiter" };
            IdentityResult roleResult;

            foreach (var roleName in roleNames)
            {
                var roleExist = await roleManager.RoleExistsAsync(roleName);
                if (!roleExist)
                {
                    roleResult = await roleManager.CreateAsync(new IdentityRole(roleName));
                }
            }

            // Create Admin user
            if (userManager.FindByNameAsync("admin").Result == null)
            {
                ApplicationUser user = new ApplicationUser
                {
                    UserName = "admin",
                    Email = "admin@example.com",
                };

                var result = await userManager.CreateAsync(user, "AdminPassword123!");
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, "Admin");
                }
            }

            // Create Waiter user
            if (userManager.FindByNameAsync("waiter").Result == null)
            {
                ApplicationUser user = new ApplicationUser
                {
                    UserName = "waiter",
                    Email = "waiter@example.com",
                };

                var result = await userManager.CreateAsync(user, "WaiterPassword123!");
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, "Waiter");
                }
            }

            // Create SuperAdmin user
            if (userManager.FindByNameAsync("superadmin").Result == null)
            {
                ApplicationUser user = new ApplicationUser
                {
                    UserName = "superadmin",
                    Email = "superadmin@example.com",
                };

                var result = await userManager.CreateAsync(user, "SuperAdminPassword123!");
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, "Admin");
                    await userManager.AddToRoleAsync(user, "Waiter");
                }
            }
        }
    }
}
