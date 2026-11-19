using System.Security.Cryptography;
using Password_Manager.core.io;
using Password_Manager.core.sqlite;

namespace Password_Manager.core.cryptography;

public class Vault
{
    private SQLiteDriver _db1;
    private SQLiteDriver _db2;

    private Vault(SQLiteDriver db1, SQLiteDriver db2)
    {
        _db1 = db1;
        _db2 = db2;
    }
    public static Vault Create(string name)
    {

        const string extension = ".vlt";

        string[] setupCommands =
        [
            @"PRAGMA foreign_keys = ON"
        ];
        string[] sqlCommandsDb1 =
        [
            @"CREATE TABLE IF NOT EXISTS status (Id INTEGER PRIMARY KEY AUTOINCREMENT, Status TEXT NOT NULL)",
            @"CREATE TABLE IF NOT EXISTS login_attempts (Id INTEGER PRIMARY KEY AUTOINCREMENT, Time_stamp DateTime NOT NULL, Status_Id INTEGER NOT NULL, FOREIGN KEY(Status_Id) REFERENCES status(Id))",
            @"INSERT INTO status (Status) VALUES ('SUCCESS'), ('FAILED')"
        ];
        string[] sqlCommandsDb2 = [
            @"CREATE TABLE IF NOT EXISTS categories (Id INTEGER PRIMARY KEY AUTOINCREMENT, Category TEXT NOT NULL)",
            @"CREATE TABLE IF NOT EXISTS vault (Id INTEGER PRIMARY KEY AUTOINCREMENT, Label TEXT, Login TEXT NOT NULL, Password TEXT NOT NULL, Category_Id INTEGER NOT NULL, FOREIGN KEY(Category_Id) REFERENCES categories(Id))",
            @"INSERT INTO categories (Category) VALUES ('General'), ('Work'), ('Internet'), ('E-Mail'), ('Banking')"
            //todo: add changelog table
        ];

        //db1 ==> LOG
        var db1 = new SQLiteDriver();
        db1.Open();
        db1.ExecuteAllQueriesString(setupCommands).ExecuteAllQueriesString(sqlCommandsDb1);
        //db2 ==> VAULT (encrypted)
        var db2 = new SQLiteDriver();
        db2.Open();
        db2.ExecuteAllQueriesString(setupCommands).ExecuteAllQueriesString(sqlCommandsDb2);
        
        byte[] db1Buffer = db1.Serialize();
        byte[] db2Buffer = db2.Serialize();
        
        byte[] db1Checksum = SHA256.HashData(db1Buffer);
        byte[] db2Checksum = SHA256.HashData(db2Buffer);

        int p = 0;
        int len = db1Buffer.Length  + 16 + db1Checksum.Length + 16 + db2Buffer.Length + 16 + db2Checksum.Length;
        byte[] buffer = new byte[len];
        for (int i = 0; i < db1Buffer.Length; i++)
        {
            buffer[i + p] = db1Buffer[i];
        }
        p = db1Buffer.Length;
        
        AddPadding(buffer, p);
        p += 16;
        
        for (int i = 0; i < db1Checksum.Length; i++)
        {
            buffer[i + p] = db1Checksum[i];
        }
        p += 32;
        
        AddPadding(buffer, p);
        p += 16;
        
        for (int i = 0; i < db2Buffer.Length; i++)
        {
            buffer[i + p] = db2Buffer[i];
        }
        p += db2Buffer.Length;
        
        AddPadding(buffer, p);
        p += 16;
        
        for (int i = 0; i < db2Checksum.Length; i++)
        {
            buffer[i + p] = db2Checksum[i];
        }
        
        FileIO.WriteFile(name + extension, buffer);
        Vault v = new Vault(db1, db2);
        db1.Close();
        db2.Close();
        
        return v;
    }

    public static Vault Open(string filename)
    {
        byte[] padding = Enumerable.Repeat<byte>(0xff, 16).ToArray();
        byte[] buffer = FileIO.ReadFile(filename);
        int part1 = 0;
        int part2 = -1, part3 = -1, part4 = -1;
        for (int i = 0; i < buffer.Length; i += 16)
        {
            var part = buffer.Skip(i).Take(16).ToArray();
            if (!Enumerable.SequenceEqual(part, padding)) continue;
            //padding found
            if (part2 == -1)
            {
                part2 = i;
            }
            else if (part3 == -1)
            {
                part3 = i;
            }
            else if (part4 == -1)
            {
                part4 = i;
            }
        }
        byte[] db1Buffer = buffer.Skip(part1).Take(part2).ToArray();
        byte[] db1Checksum = buffer.Skip(part2 + 16).Take(part3 - part2 - 16).ToArray();
        byte[] db2Buffer = buffer.Skip(part3 + 16).Take(part4 - part3 - 16).ToArray();
        byte[] db2Checksum = buffer.Skip(part4 + 16).ToArray();
        
        //validation
        byte[] db1ChecksumTest =  SHA256.HashData(db1Buffer);
        byte[] db2ChecksumTest =  SHA256.HashData(db2Buffer);
        
        if (!Enumerable.SequenceEqual(db1Checksum, db1ChecksumTest) || !Enumerable.SequenceEqual(db2Checksum, db2ChecksumTest))
        {
            throw new Exception("File was tampered with or corrupted file");
        }
        
        SQLiteDriver db1 = new SQLiteDriver(db1Buffer);
        SQLiteDriver db2 = new SQLiteDriver(db2Buffer);

        Vault v = new Vault(db1, db2);
        return v;
    }

    public void Export()
    {
        
        byte[] db1Buffer = _db1.Serialize();
        byte[] db2Buffer = _db2.Serialize();
        FileIO.WriteFile("db1.db", db1Buffer);
        FileIO.WriteFile("db2.db", db2Buffer);
    }

    private static void AddPadding(byte[] buffer, int p)
    {
        byte[] separator = [1, 1, 1, 1];
        for (int i = 0; i < 16; i++)
        {
            buffer[p + i] = 0xFF;
        }
    }
}