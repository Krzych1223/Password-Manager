using System.Runtime.InteropServices;
using Microsoft.Data.Sqlite;
using SQLitePCL;

namespace Password_Manager.core.sqlite;

public class SQLiteDriver
{
    //implement
    private readonly SqliteConnection _connection;

    /**
     * Initializes empty in-memory database
     */
    public SQLiteDriver()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
    }

    /**
     * Deserializes provided byte[] into in-memory database
     */
    public SQLiteDriver(byte[] databaseBytes)
    {
        var connection = new SqliteConnection(
            "Data Source=:memory:");

        connection.Open();

        // Allocates memory using SQLite's own allocator.
        long capacity = databaseBytes.LongLength + 1024 * 1024;

        
        IntPtr buffer = raw.sqlite3_malloc64(capacity);
        if (buffer == IntPtr.Zero)
        {
            connection.Dispose();
            throw new OutOfMemoryException();
        }
        
        Marshal.Copy(
            databaseBytes,
            0,
            buffer,
            databaseBytes.Length
        );
        
        // Let SQLite own and manage the allocated buffer.
        const int FREEONCLOSE = 1;
        const int RESIZEABLE = 2;

        int result = raw.sqlite3_deserialize(
            connection.Handle,
            "main",
            buffer,
            databaseBytes.LongLength,
            capacity,
            FREEONCLOSE | RESIZEABLE
        );

        if (result != 0)
        {
            connection.Dispose();
            throw new Exception(
                $"SQLite deserialize failed: {result}"
            );
        }

        _connection = connection;
    }

    public void Open() { _connection.Open(); }
    public void Close() { _connection.Close(); }

    public byte[] Serialize()
    {
        if (_connection.State != System.Data.ConnectionState.Open)
            _connection.Open();

        IntPtr ptr = raw.sqlite3_serialize(
            _connection.Handle,
            "main",
            out var size,
            0
        );

        if (ptr == IntPtr.Zero)
            throw new Exception("Serialization failed");

        try
        {
            byte[] result = new byte[(int)size];
            Marshal.Copy(ptr, result, 0, (int)size);
            return result;
        }
        finally
        {
            raw.sqlite3_free(ptr);
        }
    }

    public SQLiteDriver ExecuteQueryString(string query)
    {
        var command = new SqliteCommand(query, _connection);
        command.ExecuteNonQuery();
        return this;
    }

    public SQLiteDriver ExecuteQuery(SqliteCommand command)
    { 
        command.Connection = _connection;
        command.ExecuteNonQuery();
        return this; 
    }

    public SQLiteDriver ExecuteAlQueries(SqliteCommand[] commands)
    {
        foreach (var command in commands)
        {
            ExecuteQuery(command);
        }
        return this;
    }

    public SQLiteDriver ExecuteAllQueriesString(string[] queries)
    {
        foreach (var query in queries)
        {
            ExecuteQueryString(query);
        }
        return this;
    }

    public SQLiteDriver ExecuteQueryWithResult(SqliteCommand command, out SqliteDataReader reader)
    {
        command.Connection = _connection;
        reader = command.ExecuteReader();
        return this;
    }
}