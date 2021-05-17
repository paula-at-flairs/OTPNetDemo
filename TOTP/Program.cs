using OtpNet;
using System;
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
            int validForSeconds = 5;
            int otpLength = 4;

            byte[] secretBytes = Encoding.ASCII.GetBytes(secretString);
            var totp = new Totp(secretBytes, step: validForSeconds, totpSize: otpLength);
            return totp;
        }

        public static bool ValidateOTP(string userId, string otp)
        {
            var totp = GenerateOTP(userId);
            bool isTokenValid = totp.VerifyTotp(otp, out _);
            return isTokenValid;
        }
    }
}
