using System.Text;

namespace Password_Manager.core;

public static class Utils
{
    public static byte[] LongToByteArray(long l)
    {
        byte[] bytes = new byte[8];
        int p = 0;
        while (l > 0)
        {
            bytes[7 - p++] = (byte)(l % 256);
            l /= 256;
        }

        return bytes;
    }
    
    public static byte[] IntToByteArray(int i)
    {
        byte[] bytes = new byte[4];
        int p = 0;
        while (i > 0)
        {
            bytes[3 - p++] = (byte)(i % 256);
            i /= 256;
        }

        return bytes;
    }

    public static long ByteArrayToLong(byte[] bytes)
    {
        long l = 0;
        foreach (byte b in bytes)
        {
            l = (l << 8) | b;
        }
        return l;
    }

    public static string ByteArrayToString(byte[] bytes)
    {
        return Encoding.UTF8.GetString(bytes);
    }
}