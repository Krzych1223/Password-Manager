using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using ChaCha20Poly1305 = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;

namespace Password_Manager.core.cryptography.engines;

public class ChaChaCipherEngine : ICipherEngine
{
    public ChaChaCipherEngine()
    {
        
    }

    public byte[] Encrypt(byte[] data, byte[] key, int padTo = -1)
    {
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
        
        byte[] nonce = RandomNumberGenerator.GetBytes(12);

        AeadParameters parameters = new AeadParameters(
            new KeyParameter(key),
            128,
            nonce);
        
        cipher.Init(true, parameters);
        
        byte[] ciphertext = new byte[cipher.GetOutputSize(data.Length)];
        int length = cipher.ProcessBytes(data, 0, data.Length, ciphertext, 0);
        
        length += cipher.DoFinal(ciphertext, length);
        
        // Trim output if necessary
        Array.Resize(ref ciphertext, length);
        
        // Store nonce + ciphertext (tag is included)
        byte[] result = new byte[nonce.Length + ciphertext.Length];

        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, result, nonce.Length, ciphertext.Length);

        //add padding if necessary
        if (padTo == -1)
        {
            return result;
        }
        int padding = padTo - (result.Length % padTo);
        if (padding > 0 && padding < padTo)
        {
            Array.Resize(ref result, result.Length + padding);
        }

        return result;
    }

    public byte[] Decrypt(byte[] data, byte[] key, int paddedTo = -1)
    {
        if (paddedTo != -1)
        {
            int padding = 0;
            int value;
            int ptr = data.Length - 1;
            do
            {
                value = data[ptr--];
                if(value == 0) padding++;
            } while (value == 0);
            Array.Resize(ref data, data.Length - padding);
        }
        
        byte[] nonce = new byte[12];

        Buffer.BlockCopy(data, 0, nonce, 0, 12);

        byte[] ciphertext = new byte[data.Length - 12];

        Buffer.BlockCopy(
            data, 12,
            ciphertext, 0,
            ciphertext.Length
        );

        var cipher = new ChaCha20Poly1305();

        var parameters = new AeadParameters(
            new KeyParameter(key),
            128,
            nonce
        );

        cipher.Init(false, parameters);

        byte[] plaintext = new byte[cipher.GetOutputSize(ciphertext.Length)];

        int length = cipher.ProcessBytes(
            ciphertext, 0, ciphertext.Length,
            plaintext, 0
        );

        length += cipher.DoFinal(plaintext, length);

        Array.Resize(ref plaintext, length);

        return plaintext;
    }

    public byte CipherSignHex()
    {
        return 0xC0;
    }
}