using System.IO;

namespace Password_Manager.core.io;

public class DirectoryActions
{
    public string Wd()
    {
        return Directory.GetCurrentDirectory();
    }

    public DirectoryActions Cd(string dir)
    {
        Directory.SetCurrentDirectory(Path.Combine(Wd(), dir));
        return this;
    }

    public DirectoryActions CdUp()
    {
        Cd("..");
        return this;
    }

    public DirectoryActions CdUp(int num)
    {
        for (int i = 0; i < num; i++)
        {
            CdUp();
        }
        return this;
    }
}