public static class DebugReviewTest
{
    // Tijdelijk bestand om de AI-code-review op een pull request te testen.
    public static string BuildUserQuery(string userInput)
    {
        // Zet gebruikersinvoer rechtstreeks in de SQL-tekst.
        return "SELECT * FROM Users WHERE name = '" + userInput + "'";
    }
}
