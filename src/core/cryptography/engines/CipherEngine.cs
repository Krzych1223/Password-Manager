namespace Password_Manager.core.cryptography;

public interface ICipherEngine
{
    public byte[] Encrypt(byte[] data, byte[] key, int padTo = -1);
    public byte[] Decrypt(byte[] data, byte[] key, int padding = -1);

    public byte CipherSignHex();
}