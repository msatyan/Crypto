// Author: Sathyanesh Krishnan
// A simple demo for generating and validating JSON Web Token(JWT)

using System;
using System.Text;

using System.Linq;
using System.Security.Cryptography;
//using Newtonsoft.Json;


namespace MyJWT
{
    public class MyJWTv1
    {
        public static void Test1()
        {
            Byte [] Secretkey = Encoding.ASCII.GetBytes("MySecretKey");
            Byte [] FalseKey  = Encoding.ASCII.GetBytes("mySecretKey");

            String Header = "{ \"alg\": \"HS256\", \"typ\" : \"JWT\" }";

            String Payload = 
            "{ \"iss\": \"Me.com\",  \"sub\": \"Demo\", \"aud\": \"You\", \"exp\": \"t1\", \"nbf\": \"t2\", \"iat\": \"t3\", \"jti\": \"t4\"}";

            String jwt = CreateJWT(Header, Payload, Secretkey);

            Console.WriteLine("The JSON Web Token is : ");
            Console.WriteLine(jwt);
            Console.WriteLine();

            Console.WriteLine("\nTry with a valid Key.....");
            Console.WriteLine("The Given Key is {0}", 
                (ValidateJWT(jwt, Secretkey)) ? "Valid" : "Invalid");

            Console.WriteLine("\nTry with an invalid Key.....");
            Console.WriteLine("The Given Key is {0}",
                (ValidateJWT(jwt, FalseKey)) ? "Valid" : "Invalid");
        }

        public static String CreateJWT(String Header, String Payload, byte [] bSecretkey)
        {
            byte[] bHeader = Encoding.UTF8.GetBytes(Header);
            byte[] bPayload = Encoding.UTF8.GetBytes(Payload);
            byte[] Separator = Encoding.UTF8.GetBytes(".");

            String b64Header = Convert.ToBase64String( bHeader ).
                Replace('+', '-').Replace('/', '_').Replace("=", "");

            String b64Payload = Convert.ToBase64String( bPayload ).
                Replace('+', '-').Replace('/', '_').Replace("=", "");

            String UnsignedToken = b64Header + "." + b64Payload;

            byte[] bSignature = CryptoSignature(UnsignedToken, bSecretkey);

            String b64Signature = Convert.ToBase64String(bSignature).
                Replace('+', '-').Replace('/', '_').Replace("=", "");

            string jwt = UnsignedToken + "." + b64Signature;

            return (jwt);
        }

        
        public static byte[] CryptoSignature( String UnsignedToken, byte[] bSecretkey)
        {
            HMACSHA256 hmac = new HMACSHA256(bSecretkey);
            
            byte[] bUnsignedToken = Encoding.UTF8.GetBytes(UnsignedToken);
            byte[] bSignature = hmac.ComputeHash(bUnsignedToken);
           
            return (bSignature);
        }

        public static bool ValidateJWT(String jwt, byte[] bSecretkey)
        {
            bool IsValid = false;

            var parts = jwt.Split('.');
            if (parts.Length != 3)
            {
                Console.WriteLine("Bad Token: <HEADER.PAYLOAD.SIGNATURE>");
                return(IsValid);
            }

            String b64Header    = parts[0];
            String b64Payload   = parts[1];
            String b64Signature = parts[2];

            String UnsignedToken = b64Header + "." + b64Payload;

            byte[] bSignature = CryptoSignature(UnsignedToken, bSecretkey);

            String b64SignatureExpected = Convert.ToBase64String(bSignature).
                Replace('+', '-').Replace('/', '_').Replace("=", "");


            IsValid = b64SignatureExpected.SequenceEqual(b64Signature);

            if (!IsValid)
            {
                Console.WriteLine("Sig: " + b64Signature);
                Console.WriteLine("Exp: " + b64SignatureExpected);
            }

            return (IsValid);
        }
    }
}
