using Password_Manager.core;
using Password_Manager.core.cryptography;
using Password_Manager.core.io;

namespace Password_Manager;

public static class MainClass
{
    public static void Main()
    {
        DirectoryActions d = new DirectoryActions();
        
        d.CdUp(3).Cd("test_vaults");
        Console.WriteLine(d.Wd());
        byte[] password = "testtest1234141#"u8.ToArray();

        // Vault v = Vault.Create("first_vault", password);
        // v.AddEntry(new Vault.Entry("test", "Hello World!", "admin1234"u8.ToArray(), 1));
        Vault v = Vault.Open("first_vault.vlt", password);
        Vault.Entry? entry = v.GetEntryById(1, true);
        if (entry == null)
        {
            Console.WriteLine("No entry found");
        }
        else
        {
            Console.WriteLine("Found entry");
            Console.WriteLine(entry.GetLabel());
            Console.WriteLine(entry.GetLogin());
            Console.WriteLine(Utils.ByteArrayToString(entry.GetPassword()));
            Console.WriteLine(entry.GetCategoryId());
            Console.WriteLine(entry.GetCategory());
        }
    }
}