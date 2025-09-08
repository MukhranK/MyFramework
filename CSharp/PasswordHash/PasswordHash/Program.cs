using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;

int SaltSize = 128 / 8;
int HashSize = 256 / 8;
int Iterations = 100000;

string pasw = HashPassword("opanaaa");
string paswo = "opanaaaq";

bool che = VerifyHashedPassword(pasw, paswo);

Console.WriteLine(pasw);

string HashPassword(string password)
{
    if (string.IsNullOrWhiteSpace(password))
    {
        throw new ArgumentException("Password cannot be null or empty.", nameof(password));
    }

    byte[] salt = new byte[SaltSize];
    using (var rng = RandomNumberGenerator.Create())
    {
        rng.GetBytes(salt);
    }

    byte[] hash = KeyDerivation.Pbkdf2(
        password: password,
        salt: salt,
        prf: KeyDerivationPrf.HMACSHA256,
        iterationCount: Iterations,
        numBytesRequested: HashSize);

    return $"{Convert.ToBase64String(salt)}:{Convert.ToBase64String(hash)}";
}

bool VerifyHashedPassword(string hashedPassword, string providedPassword)
{
    if (string.IsNullOrWhiteSpace(hashedPassword))
    {
        throw new ArgumentException("Hashed password cannot be null or empty.", nameof(hashedPassword));
    }

    if (string.IsNullOrWhiteSpace(providedPassword))
    {
        throw new ArgumentException("Provided password cannot be null or empty.", nameof(providedPassword));
    }

    var parts = hashedPassword.Split(':');
    if (parts.Length != 2)
    {
        return false;
    }

    try
    {
        byte[] salt = Convert.FromBase64String(parts[0]);
        byte[] storedHash = Convert.FromBase64String(parts[1]);

        byte[] computedHash = KeyDerivation.Pbkdf2(
            password: providedPassword,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: Iterations,
            numBytesRequested: HashSize);

        return CryptographicOperations.FixedTimeEquals(storedHash, computedHash);
    }
    catch (FormatException)
    {

        return false;
    }
}




