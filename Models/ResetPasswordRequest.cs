using System.ComponentModel.DataAnnotations;

namespace VeriftEmailForgetPassword.Models
{
    public class ResetPasswordRequest
    {
        [Required]
        public string Token { get; set; } = string.Empty;
        [Required,MinLength(6,ErrorMessage ="Please enter at lease 6 character !!")]
        public string Password { get; set; } = string.Empty;
        [Required,Compare("Password")]
        public string ComfirmPassword { get; set; } = string.Empty;
    }
}
