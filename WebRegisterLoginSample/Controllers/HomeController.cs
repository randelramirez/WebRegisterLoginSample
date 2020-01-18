using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;
using WebRegisterLoginSample.Models;

namespace WebRegisterLoginSample.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult About()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(User user)
        {
            EncryptionService service = new EncryptionService();
            var existing = await this.TryLogin(user);

            if (existing != null)
            {
                Debug.WriteLine("Existing User");
            }
            else
            {
                Debug.WriteLine("User not found");
                return NotFound();
            }


            var attemptedPassword = service.CreatePasswordHash(user.Password, existing.PasswordSalt,
                EncryptionService.DefaultHashedPasswordFormat);

            if (attemptedPassword.Equals(existing.Password))
            {
                // authenticate and create cookie 
                var identity = new ClaimsIdentity("cookies");
                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
                identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));

                await HttpContext.SignInAsync("cookies", new ClaimsPrincipal(identity), new AuthenticationProperties());

                Debug.WriteLine("Login successful");
            }
            else
            {
                Debug.WriteLine("Failed");
            }

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(User user)
        {
            EncryptionService service = new EncryptionService();
            var saltkey = service.CreateSaltKey(EncryptionService.PasswordSaltKeySize);
            user.PasswordSalt = saltkey;
            user.Password = service.CreatePasswordHash(user.Password, saltkey, EncryptionService.DefaultHashedPasswordFormat);
            await RegisterUser(user);
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        static async Task RegisterUser(User user)
        {
            string connectionString = "Server=localhost; Database=RegistrationLogin; Trusted_Connection = True;";
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                string sql = $"INSERT INTO USERS (UserName, Password, PasswordSalt) Values ";
                sql += $"('{user.UserName}', '{user.Password}', '{user.PasswordSalt}')";



                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.CommandType = CommandType.Text;

                    await connection.OpenAsync();
                    await command.ExecuteNonQueryAsync();
                    await connection.CloseAsync();
                }

            }
        }

        public async Task<User> TryLogin(User user)
        {
            string connectionString = "Server=localhost; Database=RegistrationLogin; Trusted_Connection = True;";
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                //SqlDataReader
                await connection.OpenAsync();

                string sql = $"SELECT * FROM Users WHERE UserName = '{user.UserName}'";
                SqlCommand command = new SqlCommand(sql, connection);

                User existingUser = default(User);
                using (SqlDataReader dataReader = await command.ExecuteReaderAsync())
                {
                    if (!dataReader.HasRows)
                        return default(User);

                    while (await dataReader.ReadAsync())
                    {
                        existingUser = new User();
                        existingUser.Id = Convert.ToInt32(dataReader[nameof(WebRegisterLoginSample.Models.User.Id)]);
                        existingUser.UserName = Convert.ToString(dataReader[nameof(WebRegisterLoginSample.Models.User.UserName)]);
                        existingUser.Password = Convert.ToString(dataReader[nameof(WebRegisterLoginSample.Models.User.Password)]);
                        existingUser.PasswordSalt = Convert.ToString(dataReader[nameof(WebRegisterLoginSample.Models.User.PasswordSalt)]);

                    }
                }

                await connection.CloseAsync();
                return existingUser;
            }
        }


    }
}
