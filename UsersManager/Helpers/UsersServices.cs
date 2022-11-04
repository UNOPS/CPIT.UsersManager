using System.Dynamic;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using UsersManager.Models;
using UsersManager.DataAccess;
using UsersManager.Domain;
using UsersManager.Security;

namespace UsersManager.Helpers;

public class UsersServices
{
    private readonly ApplicationDbContext context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly JwtHandler _jwtHandler;

    public UsersServices(ApplicationDbContext context, UserManager<ApplicationUser> userManager, JwtHandler jwtHandler)
    {
        this.context = context;
        _userManager = userManager;
        _jwtHandler = jwtHandler;
    }

    public async Task<ApplicationUser> Register(UserLoginInfo info, string userEmail)
    {
        var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);

        user = await _userManager.FindByEmailAsync(userEmail);

        if (user == null)
            try
            {
                user = new ApplicationUser
                {
                    Email = userEmail,
                    UserName = userEmail
                };
                await _userManager.CreateAsync(user);

                //prepare and send an email for the email confirmation

                await _userManager.AddLoginAsync(user, info);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        else
            await _userManager.AddLoginAsync(user, info);

        return user;
    }

    public async Task<AuthResponseDto> Login(UserLoginInfo info, IConfiguration configuration, 
        ClaimPayload[]? payloads = null)
    {
        var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);

        //check for the Locked out account
        var appUser = await context.Users
            .Include(a => a.Roles)
            .ThenInclude(a => a.Role)
            .SingleOrDefaultAsync(a => a.Id == user.Id);

        appUser?.SetLastLoginDate();
        await context.SaveChangesAsync();
        
        var permissions = appUser?.GetPermissions(configuration);
        var token = await _jwtHandler.GenerateToken(appUser, null, payloads);

        return new AuthResponseDto
        {
            Token = token,
            IsAuthSuccessful = true,
            Permissions = permissions ?? new ExpandoObject()
        };
    }

    public async Task AssignRoles(ApplicationUser user, params string[] roles)
    {
        var existingRoles = await _userManager.GetRolesAsync(user);
        await _userManager.RemoveFromRolesAsync(user, existingRoles);
        await _userManager.AddToRolesAsync(user, roles);
    }
}