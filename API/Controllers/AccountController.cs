using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers{
    public class AccountController : BaseApiController{
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;
        public AccountController(DataContext context, ITokenService tokenService){
            _tokenService = tokenService;
            _context = context;
        }

        [HttpPost("register")] //POST :api/account/register
        public async Task<ActionResult<UserDto>> Register (RegisterDto registerDto){

            if(await UserExists(registerDto.Username)) return BadRequest("Username is taken!!");
            using var hmac = new HMACSHA512();  

            var user = new AppUser{
                
                UserName = registerDto.Username.ToLower(), PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),PasswordSalt = hmac.Key
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return new UserDto{
                Username = user.UserName, Token = _tokenService.CreateToken(user)
            };
        }
    
        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto){

            var user = await _context.Users.SingleOrDefaultAsync( x => x.UserName == loginDto.Username);
            if(user == null) return Unauthorized("Invalid username");

            using var hmac = new HMACSHA512(user.PasswordSalt);
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));
            for( int i=0;i<computedHash.Length;i++){
                if(computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid password");
            }

            return new UserDto{
                Username = user.UserName, Token = _tokenService.CreateToken(user)
            };
        }

        private async Task<bool> UserExists(string username){
            return await _context.Users.AnyAsync(x => x.UserName == username.ToLower() );
        }
    }
}

























// using System;
// using System.Security.Cryptography;
// using System.Text;
// using API.Data;
// using API.Entities;
// using Microsoft.AspNetCore.Mvc;
// using System.Threading.Tasks;

// namespace API.Controllers
// {
//     public class AccountController : BaseApiController
//     {
//         private readonly DataContext _context;

//         public AccountController(DataContext context)
//         {
//             _context = context;
//         }

//         [HttpPost("register")]
//         public async Task<ActionResult<AppUser>> Register(string username, string password)
//         {
//             // Step 1: Generate a random salt
//             byte[] salt = GenerateSalt();

//             // Step 2: Compute the hash of the password using SHA-512 and the salt
//             byte[] passwordHash = ComputeHash(password, salt);

//             // Step 3: Create a new AppUser instance with the provided username, password hash, and salt
//             var user = new AppUser
//             {
//                 UserName = username,
//                 PasswordHash = passwordHash,
//                 PasswordSalt = salt
//             };

//             // Step 4: Add the user to the database context
//             _context.Users.Add(user);

//             // Step 5: Save changes to the database asynchronously
//             await _context.SaveChangesAsync();

//             // Step 6: Return the registered user
//             return user;
//         }

//         private byte[] GenerateSalt()
//         {
//             // Generate a random 32-byte salt
//             byte[] salt = new byte[32];
// #pragma warning disable SYSLIB0023 // Type or member is obsolete
//             using (var rng = new RNGCryptoServiceProvider())
//             {
//                 rng.GetBytes(salt);
//             }
// #pragma warning restore SYSLIB0023 // Type or member is obsolete
//             return salt;
//         }

//         private byte[] ComputeHash(string password, byte[] salt)
//         {
//             // Combine the password and salt bytes
//             byte[] passwordAndSalt = Encoding.UTF8.GetBytes(password).Concat(salt).ToArray();

//             // Compute the SHA-512 hash
// #pragma warning disable SYSLIB0021 // Type or member is obsolete
//             using (var sha512 = new SHA512Managed())
//             {
//                 return sha512.ComputeHash(passwordAndSalt);
//             }
// #pragma warning restore SYSLIB0021 // Type or member is obsolete
//         }
//     }
//}
