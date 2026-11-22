using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Password_Manager.core.cryptography;

public class KDF
{ 
    private readonly Argon2BytesGenerator _generator;
    private readonly Argon2Parameters.Builder _paramBuilder;

    public KDF()
    {

        var builder = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
            .WithVersion(Argon2Parameters.Version13)
            .WithIterations(2)          // Liczba przebiegów (t)
            .WithMemoryAsKB(19456)      // Pamięć w KB (19 MiB)
            .WithParallelism(1);        // Liczba wątków (p)

        _paramBuilder = builder;
        Argon2Parameters parameters = builder.Build();

        // Inicjalizacja generatora i obliczenie skrótu (32 bajty)
        _generator = new Argon2BytesGenerator();
        _generator.Init(parameters);
    }
    public byte[] GenerateKey(byte[] key, out byte[] salt)
    {
        salt = RandomNumberGenerator.GetBytes(16);

        byte[] result = new byte[32];
        _paramBuilder.WithSalt(salt);
        _generator.Init(_paramBuilder.Build());
        _generator.GenerateBytes(key, result);

        return result;
    }

    public byte[] GenerateKeyWithSalt(byte[] key, byte[] salt)
    {
        _paramBuilder.WithSalt(salt);
        _generator.Init(_paramBuilder.Build());
        byte[] result = new byte[32];
        _generator.GenerateBytes(key, result);
        return result;
    }

    
    
}