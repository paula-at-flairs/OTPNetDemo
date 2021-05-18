using OtpNet;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TOTP
{
    class Program
    {
        static async Task Main(string[] args)
        {
            // https://github.com/kspearrin/Otp.NET

            var userAId = "user_a_id";
            var userBId = "user_b_id";
            var userCId = "user_c_id";

            var otpForUserA = GenerateOTP(userAId).ComputeTotp();
            var otpForUserB = GenerateOTP(userBId).ComputeTotp();
            var otpForUserC = GenerateOTP(userCId).ComputeTotp();

            Console.WriteLine($"OTP A User A: {otpForUserA}");
            Console.WriteLine($"OTP B User B: {otpForUserB}");
            Console.WriteLine($"OTP C User C: {otpForUserC}");

            var validateOtpAForUserB = ValidateOTP(userAId, otpForUserB);           // Should fail, invalid otp
            Console.WriteLine($"Using OTP A for User B: {validateOtpAForUserB}");

            var validateOtpAForUserA = ValidateOTP(userAId, otpForUserA);           // Should succeed
            Console.WriteLine($"Using OTP A for User A: {validateOtpAForUserA}");

            // Wait 10 seconds, token must have expired
            await Task.Delay(5000);

            var validateOtpCForUserC = ValidateOTP(userCId, otpForUserC);           // Should fail, token expired
            Console.WriteLine($"Using OTP C for User C: {validateOtpCForUserC}");
        }

        public static Totp GenerateOTP(string secretString)
        {
            int validForSeconds = 5 * 60;
            int otpLength = 4;

            byte[] secretBytes = Encoding.ASCII.GetBytes(secretString);
            var totp = new Totp(secretBytes, step: validForSeconds, totpSize: otpLength);

            var hashed = totp.HashOTP();
            var validHash = totp.ValidateOTPHash(hashed);

            return totp;
        }

        public static bool ValidateOTP(string userId, string otp)
        {
            var totp = GenerateOTP(userId);
            bool isTokenValid = totp.VerifyTotp(otp, out _);
            return isTokenValid;
        }
    }

    public static class TOTPExtensions
    {
        public static string HashOTP(this Totp totp)
        {
            var otp = totp.ComputeTotp();

            byte[] salt;
            new RNGCryptoServiceProvider().GetBytes(salt = new byte[16]);

            var pbkdf2 = new Rfc2898DeriveBytes(otp, salt, 100000);
            byte[] hash = pbkdf2.GetBytes(20);

            byte[] hashBytes = new byte[36];
            Array.Copy(salt, 0, hashBytes, 0, 16);
            Array.Copy(hash, 0, hashBytes, 16, 20);
            
            return Convert.ToBase64String(hashBytes);
        }

        public static bool ValidateOTPHash(this Totp totp, string hashedOTP)
        {
            /* Extract the bytes */
            byte[] hashBytes = Convert.FromBase64String(hashedOTP);
            
            /* Get the salt */
            byte[] salt = new byte[16];
            Array.Copy(hashBytes, 0, salt, 0, 16);
            
            /* Compute the hash on the password the user entered */
            var pbkdf2 = new Rfc2898DeriveBytes(totp.ComputeTotp(), salt, 100000);
            byte[] hash = pbkdf2.GetBytes(20);
            /* Compare the results */
            for (int i = 0; i < 20; i++)
                if (hashBytes[i + 16] != hash[i])
                    return false;

            return true;
        }
    }
}
