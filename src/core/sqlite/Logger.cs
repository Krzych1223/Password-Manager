using Microsoft.Data.Sqlite;
using Password_Manager.core.cryptography;

namespace Password_Manager.core.sqlite;

public class Logger
{
    private readonly SQLiteDriver _db1;
    private SQLiteDriver _db2;

    public Logger(SQLiteDriver db1)
    {
        _db1 = db1;
    }

    public void SetDb2(SQLiteDriver db2)
    {
        _db2 = db2;
    }

    public void LogAttempt(bool success)
    {
        DateTime now = DateTime.Now;
        long status = success ? 1 : 2;
        string timestamp = now.ToString("yyyy-MM-dd HH:mm:ss");

        SqliteCommand command = new SqliteCommand(
            @"INSERT INTO login_attempts (Time_stamp, Status_Id) VALUES ($timestamp, $status)");
        command.Parameters.AddWithValue("$timestamp", timestamp);
        command.Parameters.AddWithValue("$status", status);
        _db1.Open();
        _db1.ExecuteQuery(command);
        string update = @"UPDATE attempts_remaining SET Value=" + (success ? "0" : "Value+1");

        SqliteCommand updateLockCounter = new SqliteCommand(update);
        _db1.ExecuteQuery(updateLockCounter);
    }

    public void ClearLogs()
    {
        SqliteCommand[] commands =
        [
            new SqliteCommand(@"DELETE FROM login_attempts"),                                       //Truncates logs table
            new  SqliteCommand(@"UPDATE sqlite_sequence SET seq=1 WHERE name='login_attempts'") //Resets Auto-Increment counter
        ];
        _db1.Open();
        _db1.ExecuteAlQueries(commands);
    }

    public void LogAction()
    {
        
    }

    public enum Action
    {
        LOOKING_AT_RECORD = 1,
        INSERTING_NEW_RECORD = 2,
        UPDATING_EXISTING_RECORD = 3,
        DELETING_EXISTING_RECORD = 4,
        LOOKING_AT_LOGS = 5,
        TRUNCATING_LOGS = 6,
        CHANGING_PASSWORD = 7,
        CHANGING_CIPHER = 8,
    }
}