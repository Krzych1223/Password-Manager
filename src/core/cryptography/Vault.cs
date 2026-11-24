using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Org.BouncyCastle.Utilities;
using Password_Manager.core.cryptography.engines;
using Password_Manager.core.io;
using Password_Manager.core.sqlite;

namespace Password_Manager.core.cryptography;

public class Vault
{
    private readonly SQLiteDriver _db1;
    private readonly SQLiteDriver _db2;
    private readonly KDF _kdf;
    private readonly ICipherEngine _engine;
    private string FileName { get; }
    private byte[] _lockedKey;
    private byte[] _hashedKey;
    private byte[] _hashedKeySalt;
    private Logger _logger;

    private static readonly byte[] Header = [0x76, 0x61, 0x75, 0x6C, 0x74, 0xFF];

    private const string Extension = ".vlt";

    private Vault(SQLiteDriver db1, SQLiteDriver db2, KDF kdf, ICipherEngine engine, string fileName, byte[] lockedKey,
        byte[] hashedKey, byte[] hashedKeySalt,  Logger logger)
    {
        _db1 = db1;
        _db2 = db2;
        _kdf = kdf;
        _engine = engine;
        FileName = fileName;
        _lockedKey = lockedKey;
        _hashedKey = hashedKey;
        _hashedKeySalt = hashedKeySalt;
        _logger = logger;
    }

    public static Vault Create(string name, byte[] password, string cipher = "AES", bool isCompressed = false,
        bool isLocked = false)
    {
        //Initializes both databases, creates required tables and relations
        InitDatabases(out SQLiteDriver db1, out SQLiteDriver db2);
        //databases and their checksums arrays
        byte[] db1Buffer = db1.Serialize();
        byte[] db1Checksum = SHA256.HashData(db1Buffer);
        //encryption salt, key and passphrase
        byte[] s1, encryptedDb2Buffer;
        KDF argon2;
        ICipherEngine engine;
        {
            argon2 = new KDF();
            byte[] key = argon2.GenerateKey(password, out byte[] saltS1);
            s1 = saltS1;
            engine = GetEngine(cipher);

            byte[] db2Buffer = db2.Serialize();
            encryptedDb2Buffer = engine.Encrypt(db2Buffer, key, 32);
            Array.Fill(db2Buffer, (byte)0);
        }
        byte[] db2Checksum = SHA256.HashData(encryptedDb2Buffer);


        byte[] header = new byte[32];
        {

            int p = 0;
            for (int i = 0; i < 6; i++)
            {
                header[i] = Header[i];
            }

            p += 6;
            byte[] db1Size = Utils.IntToByteArray(db1Buffer.Length);
            byte[] db2Size = Utils.IntToByteArray(encryptedDb2Buffer.Length);
            for (int i = 0; i < db1Size.Length; i++)
            {
                header[i + p] = db1Size[i];
            }

            p += 4;
            header[p++] = 0x00;
            header[p++] = 0x00;
            for (int i = 0; i < db2Size.Length; i++)
            {
                header[i + p] = db2Size[i];
            }

            p += 4;
            header[p++] = 0x00;
            header[p++] = 0x00;
            byte flag;
            {
                flag = (byte)(isCompressed ? 1 : 0);
                flag |= (byte)(isLocked ? 2 : 0);
                flag |= engine.CipherSignHex();
            }
            header[p++] = flag;
            header[p++] = 0xFF;
            header[p++] = 0xFF;
            header[p++] = 0xFF;
            byte[] timestamp = Utils.LongToByteArray(DateTime.UtcNow.Ticks);
            if (isLocked)
            {
                for (int i = 0; i < timestamp.Length; i++)
                {
                    header[i + p] = timestamp[i];
                }
            }
            p += timestamp.Length;

            header[p++] = 0x00;
            header[p] = 0x00;
        }
        byte[] headerChecksum = SHA256.HashData(header); //TODO: add some sort of a salt for security
        //key hash
        byte[] passwordHash = HashEngine.SCryptHash(password, out byte[] saltS2);

        byte[] buffer = SaveDataToBuffer(
            header,
            headerChecksum,
            db1Buffer,
            db1Checksum,
            encryptedDb2Buffer,
            db2Checksum,
            s1,
            passwordHash,
            saltS2
        );

        byte[] locked = EncryptKey(password, s1, headerChecksum, engine);

        FileIO.WriteFile(name + Extension, buffer);
        Vault v = new Vault(db1, db2, argon2, engine, name + Extension, locked, passwordHash, saltS2, new Logger(db1));
        v._logger.SetDb2(db2);
        return v;
    }

    public static Vault Open(string filename, byte[] password)
    {
        byte[] padding = Enumerable.Repeat<byte>(0xff, 16).ToArray();
        byte[] buffer = FileIO.ReadFile(filename);
        int part1 = 0, //header & checksum
            part2 = -1, //db1
            part3 = -1, //db1 checksum
            part4 = -1, //db2 (vault)
            part5 = -1; //db2 checksum, key and salts
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
            else if (part5 == -1)
            {
                part5 = i;
            }
        }

        byte[] headerBuffer = buffer.Skip(part1).Take(part2).ToArray();
        byte[] header = headerBuffer.Take(32).ToArray();
        byte[] headerChecksum = headerBuffer.Skip(32).Take(32).ToArray();
        byte[] db1Buffer = buffer.Skip(part2 + 16).Take(part3 - part2 - 16).ToArray();
        byte[] db1Checksum = buffer.Skip(part3 + 16).Take(part4 - part3 - 16).ToArray();
        byte[] db2Buffer = buffer.Skip(part4 + 16).Take(part5 - part4 - 16).ToArray();
        byte[] footer = buffer.Skip(part5 + 16).ToArray();

        //extracting footer data
        byte[] db2Checksum = new byte[32], passwordHash = new byte[32], saltS1 = new byte[16], saltS2 = new byte[16];

        byte[] arraysQueue = [0, 1, 0, 1, 2, 3];
        byte[] padQueue = [0, 0, 16, 16, 0, 0];
        int ptr = 0;
        for (int i = 0; i < 6; i++)
        {
            int activeIndex = arraysQueue[i];
            int pad = padQueue[i];
            byte[] active = activeIndex switch
            {
                0 => db2Checksum,
                1 => passwordHash,
                2 => saltS1,
                _ => saltS2
            };
            for (int j = 0; j < 16; j++)
            {
                active[j + pad] = footer[j + ptr];
            }

            ptr += 16;
        }

        //checking whether file is locked
        bool isLocked = (header[18] & 0X0F) == 2;
        if (isLocked)
        {
            long timestamp = DateTime.Now.Ticks;
            long timestampFile = Utils.ByteArrayToLong(header.Skip(21).Take(8).ToArray());
            if (timestamp < timestampFile)
            {
                throw new Exception("File is locked");
            }

            header[18] ^= 0x02;     //if lock time has passed, remove flag and clear timestamp
            for (int i = 0; i < 8; i++)
            {
                header[i + 22] = 0x00;
            }
        }

        //validating checksums
        byte[] db1ChecksumTest = SHA256.HashData(db1Buffer);
        byte[] db2ChecksumTest = SHA256.HashData(db2Buffer);

        if (!Enumerable.SequenceEqual(db1Checksum, db1ChecksumTest) ||
            !Enumerable.SequenceEqual(db2Checksum, db2ChecksumTest))
        {
            throw new Exception("File was tampered with or corrupted file");
        }

        //initialization of db1
        //created before db2 decryption to record password attempts
        //todo: attempts log
        SQLiteDriver db1 = new SQLiteDriver(db1Buffer);
        Logger logger = new Logger(db1);

        //validating password
        bool arePasswordsEqual = HashEngine.SCryptValidate(passwordHash, password, saltS2);
        logger.LogAttempt(arePasswordsEqual);
        //update db1 portion of file to include logs in case of app crash
        UpdateLogsInFile(filename, db1, part4);
        if (!arePasswordsEqual)
        {
            
            throw new Exception("Invalid password!");
        }


        //decrypting db2

        KDF argon2 = new KDF();
        byte[] key = argon2.GenerateKeyWithSalt(password, saltS1);
        ICipherEngine engine = GetEngine( (header[18] & 0xF0) >> 4 == 0xA ? "AES" : "CHACHA20" );

        byte[] db2BufferDecrypted = engine.Decrypt(db2Buffer, key, 32);
        Array.Fill(db2Buffer, (byte)0);

        //initialization of db2
        SQLiteDriver db2 = new SQLiteDriver(db2BufferDecrypted);
        Array.Fill(db2BufferDecrypted, (byte)0);

        byte[] locked = EncryptKey(password, saltS1, headerChecksum, engine);

        logger.SetDb2(db2);
        Vault v = new Vault(db1, db2, argon2, engine, filename, locked, passwordHash, saltS2, logger);
        return v;
    }

    private static void UpdateLogsInFile(string filename, SQLiteDriver driver, int databasesDividerIndex)
    {
        byte[] buffer = FileIO.ReadFile(filename);
        
        byte[] serializedDriver = driver.Serialize();
        int len = serializedDriver.Length;
        byte[] length = Utils.IntToByteArray(len);
        byte[] db1Checksum = SHA256.HashData(serializedDriver);
        
        Array.Resize(ref serializedDriver, serializedDriver.Length + 48);
        for (int i = 0; i < 16; i++)
        {
            serializedDriver[i + len] = 0xFF;
        }

        for (int i = 16; i < 48; i++)
        {
            serializedDriver[i + len] = db1Checksum[i - 16];
        }


        byte[] db1LengthFromHeader = buffer.Skip(6).Take(4).ToArray();
        if (!Arrays.AreEqual(db1LengthFromHeader, length))
        {
            //length has changed, header and checksum update required
            for (int i = 0; i < 4; i++)
            {
                buffer[i + 6] = length[i];
            }

            byte[] header = buffer.Take(32).ToArray();
            byte[] checksum = SHA256.HashData(header);
            for (int i = 0; i < 32; i++)
            {
                buffer[i + 32] = checksum[i];
            }
        }
        //if lengths are equal, just update db1 content
        buffer = buffer.Take(80).Concat(serializedDriver).Concat(buffer.Skip(databasesDividerIndex)).ToArray();
        FileIO.WriteFile(filename, buffer);
    }

    private static byte[] SaveDataToBuffer(byte[] header, byte[] headerChecksum, byte[] db1Buffer, byte[] db1Checksum,
        byte[] db2Buffer, byte[] db2Checksum, byte[] db2Salt, byte[] hashedKey, byte[] hashedKeySalt)
    {
        int length = 32 + //Header
                     32 + //Header checksum
                     16 + //padding
                     db1Buffer.Length + //db1
                     16 + //padding
                     32 + //db1 checksum
                     16 + //padding
                     db2Buffer.Length + //vault
                     16 + //padding
                     96; //vault checksum, split & scrambled file password hash, vault salt and password salt

        byte[] buffer = new byte[length];
        int ptr = 0;
        for (int i = 0; i < header.Length; i++)
        {
            buffer[i + ptr] = header[i];
        }

        ptr += header.Length;
        for (int i = 0; i < headerChecksum.Length; i++)
        {
            buffer[i + ptr] = headerChecksum[i];
        }

        ptr += headerChecksum.Length;

        AddPadding(buffer, ptr);
        ptr += 16;

        for (int i = 0; i < db1Buffer.Length; i++)
        {
            buffer[i + ptr] = db1Buffer[i];
        }

        ptr += db1Buffer.Length;

        AddPadding(buffer, ptr);
        ptr += 16;

        for (int i = 0; i < db1Checksum.Length; i++)
        {
            buffer[i + ptr] = db1Checksum[i];
        }

        ptr += db1Checksum.Length;
        AddPadding(buffer, ptr);
        ptr += 16;
        for (int i = 0; i < db2Buffer.Length; i++)
        {
            buffer[i + ptr] = db2Buffer[i];
        }

        ptr += db2Buffer.Length;
        AddPadding(buffer, ptr);
        ptr += 16;
        //final 96:
        /*
         * 16B - vault checksum part 1
         * 16B - scrambled password hash part 1
         * 16B - vault checksum part 2
         * 16B - scrambled password hash part 2
         * 16B - vault salt
         * 16B - password salt
         */
        byte[] arraysQueue = [0, 1, 0, 1, 2, 3];
        byte[] padQueue = [0, 0, 16, 16, 0, 0];
        for (int i = 0; i < 6; i++)
        {
            int activeIndex = arraysQueue[i];
            int pad = padQueue[i];
            byte[] active = activeIndex switch
            {
                0 => db2Checksum,
                1 => hashedKey,
                2 => db2Salt,
                _ => hashedKeySalt
            };
            for (int j = 0; j < 16; j++)
            {
                buffer[j + ptr] = active[j + pad];
            }

            ptr += 16;
        }

        return buffer;
    }

    private static byte[] EncryptKey(byte[] password, byte[] s1, byte[] header, ICipherEngine engine)
    {
        byte[] keyPassword = HashEngine.SCryptHash(header, out byte[] saltS3);
        byte[] keyWithSalt = new byte[password.Length + 1 + s1.Length];
        Array.Copy(password, 0, keyWithSalt, 0, password.Length);
        Array.Copy(s1, 0, keyWithSalt, password.Length + 1, s1.Length);
        byte[] keyLocked = engine.Encrypt(keyWithSalt, keyPassword);

        byte[] locked = new byte[keyLocked.Length + saltS3.Length];
        Array.Copy(keyLocked, 0, locked, 0, keyLocked.Length);
        Array.Copy(saltS3, 0, locked, keyLocked.Length, saltS3.Length);

        return locked;
    }

    private static byte[] DecryptKey(byte[] locked, byte[] header, ICipherEngine engine, out byte[] s1)
    {
        byte[] s3 = locked.TakeLast(16).ToArray();
        byte[] data = locked.SkipLast(16).Take(locked.Length - 16).ToArray();
        byte[] keyPassword = HashEngine.SCryptHashWithSalt(header, s3);
        byte[] passwordWithSalt = engine.Decrypt(data, keyPassword);

        int separator = passwordWithSalt.IndexOf((byte)0);
        byte[] password = passwordWithSalt.Take(separator).ToArray();
        s1 = passwordWithSalt.Skip(separator + 1).ToArray();

        return password;
    }

    /**
    * Creates and initializes both databases.
    * Adds required tables and relations.
    */
    private static void InitDatabases(out SQLiteDriver db1, out SQLiteDriver db2)
    {
        string[] sqlCommandsDb1 =
        [
            @"CREATE TABLE IF NOT EXISTS status (Id INTEGER PRIMARY KEY AUTOINCREMENT, Status TEXT NOT NULL)",
            @"CREATE TABLE IF NOT EXISTS login_attempts (Id INTEGER PRIMARY KEY AUTOINCREMENT, Time_stamp TEXT NOT NULL, Status_Id INTEGER NOT NULL, FOREIGN KEY(Status_Id) REFERENCES status(Id))",
            @"CREATE TABLE IF NOT EXISTS attempts_remaining (Value INTEGER)",
            @"INSERT INTO attempts_remaining VALUES (0)",
            @"INSERT INTO status (Status) VALUES ('SUCCESS'), ('FAILED')"
        ];
        string[] sqlCommandsDb2 =
        [
            @"CREATE TABLE IF NOT EXISTS categories (Id INTEGER PRIMARY KEY AUTOINCREMENT, Category TEXT NOT NULL)",
            @"CREATE TABLE IF NOT EXISTS vault (Id INTEGER PRIMARY KEY AUTOINCREMENT, Label TEXT, Login TEXT NOT NULL, Password BLOB NOT NULL, Category_Id INTEGER NOT NULL, FOREIGN KEY(Category_Id) REFERENCES categories(Id))",
            @"INSERT INTO categories (Category) VALUES ('General'), ('Work'), ('Internet'), ('E-Mail'), ('Banking')"
            //todo: add changelog table
        ];

        //db1 ==> LOG
        db1 = new SQLiteDriver();
        db1.Open();
        db1.ExecuteQueryString(@"PRAGMA foreign_keys = ON").ExecuteAllQueriesString(sqlCommandsDb1);
        //db2 ==> VAULT (encrypted)
        db2 = new SQLiteDriver();
        db2.Open();
        db2.ExecuteQueryString(@"PRAGMA foreign_keys = ON").ExecuteAllQueriesString(sqlCommandsDb2);
    }

    private static ICipherEngine GetEngine(string cipherName)
    {
        cipherName = cipherName.ToUpper();
        return cipherName switch
        {
            "A" or "AES" => new AesCipherEngine(),
            "C" or "CHA" or "CHACHA20" => new ChaChaCipherEngine(),
            _ => throw new Exception("Unknown cipher: " + cipherName)
        };
    }

    /**
     * Adds a layer of 16 bytes filled with 0xFF in provided buffer on specified position,
     * to create a border between parts
     */
    private static void AddPadding(byte[] buffer, int p)
    {
        for (int i = 0; i < 16; i++)
        {
            buffer[p + i] = 0xFF;
        }
    }
    /*-----------------------------------------------------------------------------------------------*/
    /*----------------------------Vault actions------------------------------------------------------*/

    public void AddEntry(Entry entry)
    {
        byte[] key = _kdf.GenerateKey(_hashedKey, out byte[] recordSalt);
        byte[] cipherText = _engine.Encrypt(entry.GetPassword(), key);
        byte[] buffer = new byte[cipherText.Length + recordSalt.Length];
        Array.Copy(cipherText, 0, buffer, 0, cipherText.Length);
        Array.Copy(recordSalt, 0, buffer, cipherText.Length, recordSalt.Length);

        Array.Clear(entry.GetPassword(), 0, entry.GetPassword().Length);

        SqliteCommand command =
            new SqliteCommand(
                @"INSERT INTO vault (Label, Login, Password, Category_Id) VALUES ($label, $login, $password, $categoryId)");
        command.Parameters.AddWithValue("$label", entry.GetLabel());
        command.Parameters.AddWithValue("$login", entry.GetLogin());
        command.Parameters.AddWithValue("$password", buffer);
        command.Parameters.AddWithValue("$categoryId", entry.GetCategoryId());

        _db2.Open();
        _db2.ExecuteQuery(command);
    }

    public Entry? GetEntryById(long id, bool decryptPassword = false)
    {
        SqliteCommand command =
            new SqliteCommand(
                @"SELECT * FROM vault WHERE Id=$id");
        command.Parameters.AddWithValue("$id", id);

        _db2.Open();
        _db2.ExecuteQueryWithResult(command, out SqliteDataReader readerVault);

        if (!readerVault.HasRows)
        {
            return null;
        }

        readerVault.Read();

        SqliteCommand getCategory = new SqliteCommand(@"SELECT Category FROM categories WHERE Id=$id");
        getCategory.Parameters.AddWithValue("$id", (long)readerVault["category_Id"]);

        _db2.ExecuteQueryWithResult(getCategory, out SqliteDataReader readerCategory);
        readerCategory.Read();

        string label = (string)readerVault["label"];
        string login = (string)readerVault["login"];
        byte[] passwordBlob = (byte[])readerVault["password"];
        long categoryId = (long)readerVault["category_Id"];
        string category = (string)readerCategory["Category"];
        if (!decryptPassword)
        {
            Entry entry = new Entry(label, login, passwordBlob, categoryId, category);
            return entry;
        }
        byte[] recordSalt = passwordBlob.TakeLast(16).ToArray();
        byte[] passphrase = passwordBlob.SkipLast(16).ToArray();
        byte[] key = _kdf.GenerateKeyWithSalt(_hashedKey, recordSalt);
        byte[] plainPassword = _engine.Decrypt(passphrase, key);
        
        Entry e = new Entry(label, login, plainPassword, categoryId, category);
        return e;
    }

    public void UpdatePlainData(long id, string? label = null, string? login = null, long? categoryId = null)
    {
        string commandBuilder = "UPDATE vault SET ";
        bool comma = false;
        if (label != null)
        {
            commandBuilder += @"Label=$label";
            comma = true;
        }
        if (login != null)
        {
            commandBuilder += comma ? ", " : "" + @"Login=$login";
            comma = true;
        }

        if (categoryId != null)
        {
            commandBuilder += comma ? ", " : "" + @"Category_Id=$categoryId";
            comma = true;
        }
        
        commandBuilder += @" WHERE Id=$id";
        SqliteCommand command = new SqliteCommand(commandBuilder);
        command.Parameters.AddWithValue("$id", id);
        if (label != null) command.Parameters.AddWithValue("$label", label);
        if (login != null) command.Parameters.AddWithValue("$login", login);
        if (categoryId != null) command.Parameters.AddWithValue("$categoryId", categoryId);
        _db2.Open();
        _db2.ExecuteQuery(command);
    }

    public void UpdatePassword(long id, byte[] plainPassword)
    {
        string commandBuilder = "UPDATE vault SET Password=$password WHERE Id=$id";
        SqliteCommand command = new SqliteCommand(commandBuilder);
        command.Parameters.AddWithValue("$id", id);
        
        byte[] key = _kdf.GenerateKey(_hashedKey, out byte[] recordSalt);
        byte[] cipherText = _engine.Encrypt(plainPassword, key);
        byte[] buffer = new byte[cipherText.Length + recordSalt.Length];
        Array.Copy(cipherText, 0, buffer, 0, cipherText.Length);
        Array.Copy(recordSalt, 0, buffer, cipherText.Length, recordSalt.Length);

        Array.Clear(plainPassword, 0, plainPassword.Length);
        
        command.Parameters.AddWithValue("$password", buffer);
        _db2.Open();
        _db2.ExecuteQuery(command);
    }

    public void DeleteEntry(long id)
    {
        SqliteCommand command = new SqliteCommand(@"DELETE FROM vault WHERE Id=$id");
        command.Parameters.AddWithValue("$id", id);
        _db2.Open();
        _db2.ExecuteQuery(command);
    }
    public void Export(string db1Name = "db1", string db2Name = "db2")
    {
        byte[] db1Buffer = _db1.Serialize();
        byte[] db2Buffer = _db2.Serialize();
        FileIO.WriteFile(db1Name + ".db", db1Buffer);
        FileIO.WriteFile(db2Name + ".db", db2Buffer);
    }

    public void TruncateLogs()
    {
        _logger.ClearLogs();
        Save();
    }

    public void Save()
    {
        //read the vault file and extract header
        byte[] fileBuffer = FileIO.ReadFile(FileName);
        byte[] header = fileBuffer.Take(32).ToArray();
        //serializing databases
        byte[] db1Buffer = _db1.Serialize();
        byte[] db2Buffer = _db2.Serialize();
        //calculate byte-array lengths of db1
        byte[] db1Length = Utils.IntToByteArray(db1Buffer.Length);
        //generate sha256 checksum of db1
        byte[] db1Checksum = SHA256.HashData(db1Buffer);

        //override db1 length written in header
        header[6] = db1Length[0];
        header[7] = db1Length[1];
        header[8] = db1Length[2];
        header[9] = db1Length[3];

        //recalculate header checksum
        byte[] newHeaderChecksum = SHA256.HashData(header);

        //acquire file key from its encrypted storage
        byte[] headerChecksum = fileBuffer.Skip(32).Take(32).ToArray();
        byte[] password = DecryptKey(_lockedKey, headerChecksum, _engine, out byte[] s1);
        //using argon2 kdf generate new db2 encryption key
        byte[] key = _kdf.GenerateKey(password, out byte[] salt);
        //replaces old password with a new one in app-memory if header has changed
        _lockedKey = EncryptKey(password, salt, newHeaderChecksum, _engine);
        //wipe un-encrypted password
        Array.Clear(password, 0, password.Length);
        //encrypt db2 buffer with new key
        db2Buffer = _engine.Encrypt(db2Buffer, key, 32);
        //calculate byte-array lengths of encrypted db2
        byte[] db2Length = Utils.IntToByteArray(db2Buffer.Length);
        //generate checksum for encrypted db2
        byte[] db2Checksum = SHA256.HashData(db2Buffer);
        //override db2 length written in header
        header[12] = db2Length[0];
        header[13] = db2Length[1];
        header[14] = db2Length[2];
        header[15] = db2Length[3];


        byte[] buffer = SaveDataToBuffer( header, newHeaderChecksum, 
            db1Buffer, db1Checksum,
            db2Buffer, db2Checksum, salt,
            _hashedKey, _hashedKeySalt
        );

        FileIO.WriteFile(FileName, buffer);
    }

    public class Entry(string label, string login, byte[] password, long categoryId, string? category = null)
    {
        private string _label = label;
        private string _login = login;
        private byte[] _password = password;
        private long _categoryId = categoryId;
        private string? _category = category;

        public string GetLabel() { return _label; }
        public string GetLogin() { return _login; }
        public byte[] GetPassword() { return _password; }
        public long GetCategoryId() { return _categoryId; }
        public string? GetCategory() { return _category; }
    }
}