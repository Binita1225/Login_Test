using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Login_Test.Models
{
    public class User
    {
        [Key]
        public int Id { get; set; }
        public string UserName { get; set; }
        [PasswordPropertyText]
        public string Password { get; set; }

    }
}
