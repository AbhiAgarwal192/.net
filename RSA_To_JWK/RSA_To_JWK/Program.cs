using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace RSA_To_JWK
{
    class Program
    {
        static void Main(string[] args)
        {
            var publicKey = @"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDEDtIRT57TJAfmub2RsIM32jdo
8ijsds/u1fpY6hwtkC01/LFJkNTXqSwvpaO5tp86o0SlzBHdF0WxPtsKqdc8F7kQ
uHm7hUTLX0zPGRdGCsy9q/PIGlVGAFTBSVXl+grmGGZuS1CHI13L/oulBGENQOxO
8r6D1RyPjt6z0BAndQIDAQAB
-----END PUBLIC KEY-----";
            using (var textReader = new StringReader(publicKey))
            {
                var pubKeyReader = new PemReader(textReader);
                RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)pubKeyReader.ReadObject();
                var e = Base64UrlEncoder.Encode(rsaKeyParameters.Exponent.ToByteArrayUnsigned());
                var n = Base64UrlEncoder.Encode(rsaKeyParameters.Modulus.ToByteArrayUnsigned());
                var dict = new Dictionary<string, string>() {
                    {"e", e},
                    {"kty", "RSA"},
                    {"n", n}
                };
                var hash = SHA256.Create();
                Byte[] hashBytes = hash.ComputeHash(System.Text.Encoding.ASCII.GetBytes(JsonConvert.SerializeObject(dict)));
                JsonWebKey jsonWebKey = new JsonWebKey()
                {
                    Kid = Base64UrlEncoder.Encode(hashBytes),
                    Kty = "RSA",
                    E = e,
                    N = n
                };

                Console.WriteLine(jsonWebKey);
                Console.ReadLine();
            }
        }
    }
}
