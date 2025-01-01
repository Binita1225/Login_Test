using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Login_Test.Migrations
{
    /// <inheritdoc />
    public partial class changestringtobyteinuser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Step 1: Add a temporary column for binary data
            migrationBuilder.AddColumn<byte[]>(
                name: "SaltTemp",
                table: "Users",
                type: "varbinary(max)",
                nullable: true); // Allow null temporarily

            // Step 2: Copy data from the old column (Salt) to the new column (SaltTemp)
            migrationBuilder.Sql("UPDATE Users SET SaltTemp = CONVERT(varbinary(max), Salt)");

            // Step 3: Remove the old Salt column
            migrationBuilder.DropColumn(name: "Salt", table: "Users");

            // Step 4: Rename the temporary column to Salt
            migrationBuilder.RenameColumn(name: "SaltTemp", newName: "Salt", table: "Users");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Reverse the process to bring back the old Salt column
            migrationBuilder.AddColumn<string>(
                name: "Salt",
                table: "Users",
                type: "nvarchar(max)",
                nullable: true);

            // Remove the binary column
            migrationBuilder.DropColumn(name: "Salt", table: "Users");
        }
    }
}
