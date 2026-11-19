
using System.IO;

namespace Password_Manager.core.io;

public class FileIO
{
    public static byte[] ReadFile(string filename)
    {
        byte[] buffer = File.ReadAllBytes(filename);
        return buffer;
    }

    public static void WriteFile(string filename, byte[] buffer)
    {
        File.WriteAllBytes(filename, buffer);
    }
    
}