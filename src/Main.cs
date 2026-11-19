using System.IO;
using System.Text;
using Password_Manager.core.cryptography;
using Password_Manager.core.io;
using Password_Manager.core.sqlite;

namespace Password_Manager;

public static class MainClass
{
    public static void Main()
    {
        DirectoryActions d = new DirectoryActions();
        
        d.CdUp(3).Cd("test_vaults");
        Console.WriteLine(d.Wd());
        byte[] buffer = FileIO.ReadFile("test_rw.txt");
        Console.WriteLine(ByteToString(buffer));

        Vault v = Vault.Open("first_test_vault.vlt");
        v.Export();
        /*var db = new SQLiteDriver();
        db.Open();
        {
            db.ExecuteQueryString(@"CREATE TABLE test(ID INTEGER PRIMARY KEY AUTOINCREMENT, LOGIN VARCHAR NOT NULL);");
            db.ExecuteQueryString(@"INSERT INTO test (LOGIN) VALUES ('test1');");
            db.ExecuteQueryString(@"INSERT INTO test (LOGIN) VALUES ('test2');");
            db.ExecuteQueryString(@"INSERT INTO test (LOGIN) VALUES ('test3');");
            db.ExecuteQueryString(@"INSERT INTO test (LOGIN) VALUES ('test4');");
        }
        byte[] buffer2 = db.Serialize();
        
        FileIO.WriteFile("database.db", buffer2);*/
    }

    private static string ByteToString(byte[] buffer)
    {
        return Encoding.UTF8.GetString(buffer);
    }
}