using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;

namespace Password_Manager.core.cryptography.engines;

public static class HashEngine
{
    
    public static byte[] SCryptHash(byte[] data, out byte[] salt)
    {
        const int saltBytes = 16;
        salt = RandomNumberGenerator.GetBytes(saltBytes);
        return SCryptHashWithSalt(data, salt);
    }

    public static byte[] SCryptHashWithSalt(byte[] data, byte[] salt)
    {
        const int n = 1 << 17, r = 8, p = 1, keyBytes = 32;
        byte[] hash = SCrypt.Generate(data, salt, n, r, p, keyBytes);
        return hash;
    }

    public static bool SCryptValidate(byte[] hash, byte[] data, byte[] salt)
    {
        byte[] test = SCryptHashWithSalt(data, salt);
        return test.SequenceEqual(hash);
    }
}