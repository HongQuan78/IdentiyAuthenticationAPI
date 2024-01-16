
using System.Net;
using System.Net.Mail;

namespace JWTAuthenticationAPI.Services
{
    public class EmailSender : IEmailSender
    {
        private readonly IConfiguration _configuration;

        public EmailSender(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task SendEmailAsync(string fromAddress, string toAddress, string subject, string messsage)
        {
            var emailMessage = new MailMessage(fromAddress, toAddress, subject, messsage);
            using (var client = new SmtpClient("smtp.gmail.com")
            {   
                Port = 587,
                UseDefaultCredentials = false,
                EnableSsl = true,
                Credentials = new NetworkCredential("qanvo313@gmail.com", "hoip imxj sttx xcwh")
            })
            {
                await client.SendMailAsync(emailMessage);
            }
        }
    }
}
