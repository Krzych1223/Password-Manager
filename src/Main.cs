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
        Vault v = Vault.Open("first_vault.vlt", password);
        v.AddEntry(new Vault.Entry("test", "Hello World!", "admin1234"u8.ToArray(), 1));
        Select(v, 1);
        Console.WriteLine("----------------------------------------");
        v.UpdatePlainData(1, categoryId: 2);
        v.UpdatePassword(1, "abcdtest1234"u8.ToArray());
        Select(v, 1);
        Select(v, 2);
        v.DeleteEntry(2);
        v.Export();
        //v.Export();
    }

    private static void Select(Vault v, long id)
    {
        Vault.Entry? entry = v.GetEntryById(id, true);
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