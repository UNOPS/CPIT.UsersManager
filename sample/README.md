# Sample Application

This sample application demonstrates how to use the UsersManager library with both PostgreSQL and MySQL databases.

## Project Structure

```
Sample/
├── SampleApp/
│   ├── Controllers/
│   │   └── UsersController.cs    # Simple controller demonstrating library usage
│   ├── Properties/
│   │   └── launchSettings.json    # Launch configuration
│   ├── appsettings.json           # Default configuration (PostgreSQL)
│   ├── appsettings.MySQL.json     # MySQL configuration override
│   ├── appsettings.Development.json
│   ├── Program.cs                 # Application startup
│   └── SampleApp.csproj           # Project file
└── README.md                       # This file
```

## Configuration

### Using PostgreSQL (Default)

The default `appsettings.json` is configured for PostgreSQL:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Port=5432;Database=UsersManagerSample;User Id=postgres;Password=postgres;"
  },
  "DatabaseProvider": "PostgreSQL"
}
```

### Using MySQL

To use MySQL, you can either:

1. **Modify appsettings.json** and change:
   - `DatabaseProvider` to `"MySQL"`
   - `DefaultConnection` to your MySQL connection string

## Running the Sample

1. **Update Connection Strings**
   - Edit `appsettings.json` with your database credentials
   - Make sure your database server is running

2. **Create Database Migrations**
   ```bash
   cd SampleApp
   dotnet ef migrations add InitialCreate
   dotnet ef database update
   ```

3. **Run the Application**
   ```bash
   dotnet run
   ```

4. **Test the API**
   - Open `http://localhost:5000/swagger` in your browser
   - Try the `/api/users/test` endpoint to verify the library is working
   - Try the `/api/users/database-info` endpoint to see which database provider is configured

## API Endpoints

- `GET /api/users/test` - Simple test endpoint to verify the library is configured
- `GET /api/users/database-info` - Returns information about the configured database provider

## Switching Between Databases

The library automatically detects the database provider from the `DatabaseProvider` setting in your configuration. Simply change this value and update your connection string to switch between PostgreSQL and MySQL.

**Important:** When switching databases, you'll need to:
1. Update the `DatabaseProvider` setting
2. Update the connection string
3. Create new migrations for the new database provider
4. Apply the migrations to create the schema
