using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Login_Test.Services
{
    public interface IJwtService
    {
        string GenerateToken(string username, string role);
        ClaimsPrincipal? ValidateToken(string token);
    }

    public class JwtService : IJwtService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<JwtService> _logger;

        public JwtService(IConfiguration configuration, ILogger<JwtService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        private string Key => _configuration["JwtSettings:Key"];
        private string Issuer => _configuration["JwtSettings:Issuer"];
        private string Audience => _configuration["JwtSettings:Audience"];

        public string GenerateToken(string username, string role)
        {
            var claims = new[] 
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Role, role)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Key));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var expiration = DateTime.Now.AddMinutes(30);

            var token = new JwtSecurityToken(
                issuer: Issuer,
                audience: Audience,
                claims: claims,
                expires: expiration,
                signingCredentials: credentials
            );

            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            // Log the generated token (remove this in production)
            _logger.LogInformation($"Generated JWT Token: {tokenString}");

            return tokenString;
        }

        public ClaimsPrincipal? ValidateToken(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(Key);
                var parameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidIssuer = Issuer,
                    ValidAudience = Audience,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ClockSkew = TimeSpan.Zero  // Remove the default 5-minute tolerance
                };

                var principal = tokenHandler.ValidateToken(token, parameters, out var validatedToken);

                // Log successful validation (for debugging)
                _logger.LogInformation("Token successfully validated.");

                return principal;
            }
            catch (Exception ex)
            {
                // Log the exception and return null if validation fails
                _logger.LogError($"Token validation failed: {ex.Message}");
                return null;
            }
        }
    }
}
