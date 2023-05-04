using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using Microsoft.AspNetCore.Http;

namespace IM_Tool.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        private readonly ILogger<WeatherForecastController> _logger;

        public WeatherForecastController(ILogger<WeatherForecastController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        public IEnumerable<WeatherForecast> Get()
        {
            var rng = new Random();
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = rng.Next(-20, 55),
                Summary = Summaries[rng.Next(Summaries.Length)]
            })
            .ToArray();
        }

        [HttpGet]
        [Route("/ExistingUserLogin/{username}/{password}")]
        public IActionResult GetExistingUserLogin(string username,string password)
        {
        var UE = new UnicodeEncoding();
        byte[] passwordBytes = UE.GetBytes(username);
        byte[] aesKey = SHA256.HashData(passwordBytes);
        byte[] aesIV =MD5.HashData(passwordBytes);
        var secretKey = Encoding.UTF8.GetString(aesKey);
        var encryptedUser = EncryptUsingAES(username,aesKey,aesIV);
        var encryptedUserString = Encoding.UTF8.GetString(encryptedUser,0,encryptedUser.Length);
        var cookieOptions = new CookieOptions{Expires = DateTime.Now.AddDays(30)};
        HttpContext.Response.Cookies.Append("Legacy_User", Base64Encode(username),cookieOptions);
        HttpContext.Response.Cookies.Append("Secret_Key", secretKey , cookieOptions);
        HttpContext.Response.Cookies.Append("New_User", encryptedUserString,cookieOptions);
        return Ok("Encrypted user is "+ encryptedUserString);
        }

private static byte[] EncryptUsingAES(string plainText, byte[] Key, byte[] IV) 
{
        byte[] encrypted;
        using(AesManaged aes = new AesManaged()) {
            ICryptoTransform encryptor = aes.CreateEncryptor(Key, IV);
            using(MemoryStream ms = new MemoryStream()) {
                using(CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write)) {
                    using(StreamWriter sw = new StreamWriter(cs))
                    sw.Write(plainText);
                    encrypted = ms.ToArray();
                }
            }
        }
        return encrypted;
}

    private static string DecryptUsingAES(byte[] cipherText, byte[] Key, byte[] IV) 
    {
        string plaintext = null;
        using(AesManaged aes = new AesManaged()) {
            ICryptoTransform decryptor = aes.CreateDecryptor(Key, IV);
            using(MemoryStream ms = new MemoryStream(cipherText)) {
                using(CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read)) {
                    using(StreamReader reader = new StreamReader(cs))
                    plaintext = reader.ReadToEnd();
                }
            }
        }
        return plaintext;
    }
        private static byte[] EncryptUsingTripleDES(string plainText, byte[] Key, byte[] IV) 
        {  
        byte[] encrypted;  
        using(TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider()) 
        {  
            ICryptoTransform encryptor = tdes.CreateEncryptor(Key, IV);  
            using(MemoryStream ms = new MemoryStream()) {  
                using(CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write)) {  
                    using(StreamWriter sw = new StreamWriter(cs))  
                    sw.Write(plainText);  
                    encrypted = ms.ToArray();  
                }  
            }  
        }  
        return encrypted;  
        }  

    private static string DecryptUsingTripleDES(byte[] cipherText, byte[] Key, byte[] IV)
     {  
        string plaintext = null;  
        using(TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider()) {  
            ICryptoTransform decryptor = tdes.CreateDecryptor(Key, IV);  
            using(MemoryStream ms = new MemoryStream(cipherText)) {  
                using(CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read)) {  
                    using(StreamReader reader = new StreamReader(cs))  
                    plaintext = reader.ReadToEnd();  
                }  
            }  
        }  
        return plaintext;  
     }

     private static byte[] EncryptionUsingRES(byte[] Data, RSAParameters RSAKey, bool DoOAEPPadding)  
{  
 try  
 {  
 byte[] encryptedData;  
 using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())  
   {  
    RSA.ImportParameters(RSAKey);  
           encryptedData = RSA.Encrypt(Data, DoOAEPPadding);  
   }   return encryptedData;  
 }  
 catch (CryptographicException e)  
 {  
 Console.WriteLine(e.Message);  
 return null;  
 }  
} 

private static byte[] DecryptionUsingRES(byte[]Data, RSAParameters RSAKey, bool DoOAEPPadding)  
{  
 try  
 {  
 byte[] decryptedData;  
 using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())  
    {  
     RSA.ImportParameters(RSAKey);  
     decryptedData = RSA.Decrypt(Data, DoOAEPPadding);  
    }  
 return decryptedData;  
 }  
 catch (CryptographicException e)  
 {  
 Console.WriteLine(e.ToString());  
 return null;  
 }          
}
private static string Base64Encode(string plainText){
    var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
    return System.Convert.ToBase64String(plainTextBytes);
}
    }
}
