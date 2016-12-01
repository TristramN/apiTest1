using System;
using System.Collections.Generic;
using System.IO;
using Jose;
using Org.BouncyCastle.Crypto.Parameters;

namespace apiTest1
{
    public static class Encode
    {
        // private_key from the Service Account JSON file
        private const string FirebasePrivateKey =
            @"-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDQFidypNktOK18\nbyra89B4Wt1znj6qQyuwThAm+/hV3Vis8tpd6l3ApEMODhMrRKSiL0Z04V2IIv3B\n1awRBi/s46Frv/A15bK1mxHAulR5Lcxp+jBmo/aLBioH2MPRdsHu2P7e0zs+/2OC\newbluCTiQQ0JH6RxAuFjsDggKq3yGaZ764phrjWRz9WQaS4f2xpDHENXAngE3/pv\ncxG7T+n1ha0pKQwc0FG6/uDcsUkPzeP1ZoIpTEUlaA1rRTaThEuGiynBbYZDh2Dx\nGGyufZIi2vrLoBAqEWdoXmHdOZ0iBPPv0uLG/Wj6p4vnorOoeir8nl7yN8Zp7Sho\nTi37YHGLAgMBAAECggEBAM2GNCw9ueu6YU/YFQHxcuSNCtFZaReOBKa8U6PNlzhn\nyV/49clw5GyTUU+egzxnLhyqiPKEbXc66Fv9CVg/PjLBmfvstfrmBp7srJoo76pI\nm+/Ilump5Kbnzbe2V6KZo26fkQzQoWHVqZmEngli2btG+PMb97VPXQKzWJwcy3Wk\nLAuW2/vuQA/2+hAddl2fEq6QLPeWz35+uEZEOolXjQTctiL7E4x8r/Zv4EgQDgE+\n5J/VGpvehJRwd9bZUfjV6NaEKssqlXtj5HKg1XK8Kuc+A5BroyjblqVC40tw6dpz\nRVEzs4jNi1OeHajWKTNen1jXkCACTyfM4H70x2ILlOECgYEA6+tirvWMMPjrdqLK\nJSibJQ+tkjuh8daS4w2Ib5vwvRHnttYh/Y1F7NO/a5KGAgvg30Li36Xf5SrF91O5\n2Q9j6jNs/NxgX4+sbJPZJEmZHIGjgWs0Bbf4v4or48SESepM989WqTHtfIzAeKQm\n+Jt3F943Vw0GwpVELcD4KtYMsBkCgYEA4cxMHJiJlrCkGo9Gd6KaAmtqFxayAaOy\nfd2Xg5/HXpOkb7WB5szLAeJeQYlJqqA+Rql5cf2uKqvW9koZX80qdWHXhyfmPYvN\nehfDO8GIhISuuAEq7+P+ggo/pvkThoHWN4sU0UYmZQyA+oqyHj/NKKa7WGMK0GSa\nI6KHmvJwk0MCgYAa1EkDtp77zsMQWdD9StHh9Bd8ItX2570KnzZd4vEMv2WHkHCL\nIi7KkQYa2K3uu6UWHsgoQPfmWufqiZYADlUBhFmno/Q9ydwE+QdfrhMAf+m1RRjE\ncbiTJ8Z3/5g/w6p/IBAt66SjXmphDeH0sdFoYHgQqUWUiV8YiPJwBKmquQKBgD2+\ngN2c9JrJSMaegTV7uEOLHeKcaSa7nbZ/Xsw2Z+070E5fwtrbC3RDc2TWZteKpBzs\ngPIj3Xl7rfeBQbkJwF+C1s31oicYUKLfVprDjFI4ehKE9znMDa9/n/JH0AgK/woH\nNTUYyqz9I1Pfk19kMPS5yycbRjzAFcpCynQbcZ9DAoGBAOLUllUQ7IUFNL98+cDs\n3e2x8wa22nwA/9TjjjmU/Xo2CbytuwwWY4zps/Uijlcu+9oZ2OY2V8jzZYS1sfEp\nrtQBHlAUltHfP1ePiMZHYYo+x9jOHr8WKbsNxciZlulATiipOXPSD5YMhRyV9jzw\nHC3WX4SfIg7lrq068ZvPDj3w\n-----END PRIVATE KEY-----\n";

        // Same for everyone
        private const string FirebasePayloadAud =
            "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";

        // client_email from the Service Account JSON file
        private const string FirebasePayloadIss = "firebaseauth@test-f9bcb.iam.gserviceaccount.com";
        private const string FirebasePayloadSub = "firebaseauth@test-f9bcb.iam.gserviceaccount.com";

        // the token 'exp' - max 3600 seconds - see https://firebase.google.com/docs/auth/server/create-custom-tokens
        private const int FirebaseTokenExpirySecs = 3600;

        private static RsaPrivateCrtKeyParameters _rsaParams;
        private static readonly object RsaParamsLocker = new object();

        public static string EncodeToken(string uid)
        {
            // Get the RsaPrivateCrtKeyParameters if we haven't already determined them
            if (_rsaParams == null)
            {
                lock (RsaParamsLocker)
                {
                    if (_rsaParams == null)
                    {
                        var sr = new StreamReader(GenerateStreamFromString(FirebasePrivateKey.Replace(@"\n", "\n")));
                        var pr = new Org.BouncyCastle.OpenSsl.PemReader(sr);
                        _rsaParams = (RsaPrivateCrtKeyParameters) pr.ReadObject();
                    }
                }
            }

            var claims = new Dictionary<string, object>
            {
                {"premium_account", true}
            };

            var payload = new Dictionary<string, object>
            {
                {"claims", claims},
                {"uid", uid},
                {"iat", SecondsSinceEpoch(DateTime.UtcNow)},
                {"exp", SecondsSinceEpoch(DateTime.UtcNow.AddSeconds(FirebaseTokenExpirySecs))},
                {"aud", FirebasePayloadAud},
                {"iss", FirebasePayloadIss},
                {"sub", FirebasePayloadSub}
            };

            return Jose.JWT.Encode(payload, Org.BouncyCastle.Security.DotNetUtilities.ToRSA(_rsaParams),
                JwsAlgorithm.RS256);
        }

        private static long SecondsSinceEpoch(DateTime dt)
        {
            var t = dt - new DateTime(1970, 1, 1);
            return (long) t.TotalSeconds;
        }

        private static Stream GenerateStreamFromString(string s)
        {
            var stream = new MemoryStream();
            var writer = new StreamWriter(stream);
            writer.Write(s);
            writer.Flush();
            stream.Position = 0;
            return stream;
        }
    }
}