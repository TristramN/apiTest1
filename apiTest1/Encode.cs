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
            "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDbkOWgiSSGfewL\nIu0rqBKd+1af23TymyM3cGk6HgoDPRZqLcC005R9tyjFcKruNPhzR7zALXV2GLqp\nm6YMzRZKOCMyI1IiCnnyM2usyVKeA3/ALCAi67+MDmxjA/Ic8cwM7MEcEuY/CHpB\n04JZpAmO7FiIHWzmTLjintM1f6az8T6STXtVFlBTB6MdTl0+WZJc1vwVONtj8YUC\nv3lp/YaqIsrjwECTvii5ymUGEUyYC+fqqkWbABuUhVN5W8EJuhbGGVoJT07iIO09\nAkbQ+YwxF+sM1PjUgieYSGnljL2s4ve3367D7hdSqk0WPzxCntnEn3I2r76aeFC/\nHu7zUiKXAgMBAAECggEBAMgA+0r64gyo08VpMUXdOegytLu1Ophr/O5ZNWE9T72X\nfb2Go82UFeVWXItNkEagddj89dDRF/hVmmM5Z06t2qoM7PKU/hIIHQElGeYxFVLe\nuRYim7tzp+46jTy8sWTwVQFJALdD9/xfCo6/zjM9m39Xh2Wl+DbomFnGd3p6Jy4s\n2CIbPlknUKVjaPwGKAsQRkh4UfEyey636WPHnqVP2NOvLhEOEf0XD6ZzVmMymZSe\ntv8eYjPJYLo2UG27u3l8R88tz32ba4qXXPpVgZ94Yk6kpYX2QHbCwqzj0dghIm/x\ndCgBcPSFul2lGoJtIj0oFz111NCB3ahQnVzrDUVHWqECgYEA/D+9Lq3vI6NW8z8b\nVNOYlepi45SfCI+xqri3AsOmtasSXespFFQCtaXdk9Ip8NnJ0LTM5p1lV8WNG6kl\nka8KPlGl4Ey9U3fhSDIBRXPV06IKh9QNAVbNjCbHz3PGSIEsOMWoJkrtqKTkWCVr\nIgtpK46AZpcU1dEG4vsTbRbnum8CgYEA3tS9kHLP5HGCo12ojm/QCDgsb/EdOyg3\nnmjNHL0BNIUj/V9jTDVm0DzmPET+Ev34w2JnuLVtL+iQ5Odx2LWOVOKVZIm5jsbE\nndtvwzBGnHDMg6NsHFBu9+qteO+uwiYYwfnaC4wonjZkAQBWHFmXaqf+1ub50PGF\nGJg1a3mTzlkCgYA6JG70zX6rlkC6fLdODB/FnmsAzgcCMCzhjwYQCwzoHvBy2Xt0\nhhDB0eOK6Qxlya1s/9+i4HC1lIF7+LcCJ3iS+LrlQor5LE6vF2eXnKWSzGzk9gmx\nX1KtlVrFBIiVucB5rYWenfK9xpQjhSx2gm7RbV1HSFezGSUfOIQ3xunO3QKBgQDL\njXT5LhhAq3xV9amTLArSZ1YYkB5OuudL2pp8BR/DtVfyDZ/srt+Tm/4J0lByUvRa\nr1rmfT0XxZAOumniN7+kRTOJGtKZ3XMgbKMEn+Xw5I2+Npv8pXEpIYSD9BclHZ4C\nHFYVtFwqYq8pxv/id+j8sif2chqExwv5Mpmh6vadSQKBgG2KKXInBjIQpDGzBjHK\n24whwcvrz4mzunmYVyKNbPqLC1tkL60hSzX03c2rdHPaZSXfBqll/ez7SQOIbN1A\n8rztQbngii6CU04DzA52101ZFGDolU+vQfM4O7K12mJOWXNEwASl0vN88MqTCGrR\n9GfYqHGg+H5U6MUZ/EyuP3FP\n-----END PRIVATE KEY-----\n";

        // Same for everyone
        private const string FirebasePayloadAud =
            "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";

        // client_email from the Service Account JSON file
        private const string FirebasePayloadUrl = "firebase-adminsdk-szyhq@test-f9bcb.iam.gserviceaccount.com";

        // the token 'exp' - max 3600 seconds - see https://firebase.google.com/docs/auth/server/create-custom-tokens
        private const int FirebaseTokenExpirySecs = 2600;

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
                        var sr = new StreamReader(GenerateStreamFromString(FirebasePrivateKey));
                        var pr = new Org.BouncyCastle.OpenSsl.PemReader(sr);
                        _rsaParams = (RsaPrivateCrtKeyParameters) pr.ReadObject();
                    }
                }
            }

            var payload = new Dictionary<string, object>
            {
                {"uid", uid},
                {"iat", SecondsSinceEpoch(DateTime.UtcNow)},
                {"exp", SecondsSinceEpoch(DateTime.UtcNow.AddSeconds(FirebaseTokenExpirySecs))},
                {"aud", FirebasePayloadAud},
                {"iss", FirebasePayloadUrl},
                {"sub", FirebasePayloadUrl},
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