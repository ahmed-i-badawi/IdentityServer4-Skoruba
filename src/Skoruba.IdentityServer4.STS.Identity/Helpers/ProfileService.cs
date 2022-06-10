using IdentityServer4.Models;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using Skoruba.IdentityServer4.Admin.EntityFramework.Entities;
using Skoruba.IdentityServer4.Admin.EntityFramework.Shared.DbContexts;
using Skoruba.IdentityServer4.Admin.EntityFramework.Shared.Entities.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;



namespace Skoruba.IdentityServer4.STS.Identity.Helpers
{
    public class ProfileService : IProfileService
    {
        private readonly UserManager<UserIdentity> _userManager;
        private AdminIdentityDbContext _context { get; set; }
        public ProfileService(UserManager<UserIdentity> userManager, AdminIdentityDbContext context)
        {
            _userManager = userManager;
            _context = context;
        }

        public async Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var userId = context.Subject.FindFirst("sub").Value;
            var requestedScopes = context.RequestedResources.Resources.ApiScopes.Select(s => s.Name).ToList();
            var claimsTypesBasedOnScope = context.RequestedClaimTypes.ToList();
            List<string> roles;

            var user = await _userManager.FindByIdAsync(userId);

            var userRolesIds = await _context.UserRoles.Where(u => u.UserId == userId)
            .Select(s => s.RoleId).ToListAsync();

            roles = await _context.Roles.Where(r => userRolesIds.Contains(r.Id)).Select(r => r.Name).ToListAsync();

            context.IssuedClaims.AddRange(context.Subject.Claims.Where(c => claimsTypesBasedOnScope.Contains(c.Type)));
            context.IssuedClaims.Add(new Claim("FullName", user.FullName ?? user.Id));


            context.IssuedClaims.Add(new Claim("name", user.UserName));
            context.IssuedClaims.Add(new Claim("role", string.Join(" ", roles)));

        }

        public async Task IsActiveAsync(IsActiveContext context)
        {
            var userId = context.Subject.FindFirst("sub").Value;
            var selectedUser = await _userManager.FindByIdAsync(userId);
            if (selectedUser!=null)
            {
                context.IsActive = true;
            }
        }
    }
}

