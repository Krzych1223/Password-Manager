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
        Vault v = Vault.Open("chacha.vlt", password, cipher: "ChaCha20");
        SelectAll(v);
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

    private static void SelectAll(Vault v)
    {
        int id = 1;
        Vault.Entry? entry;
        do
        {
            entry = v.GetEntryById(id++, true);
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
            Console.WriteLine("----------------");
        } while (entry != null);
    }
}