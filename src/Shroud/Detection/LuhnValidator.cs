namespace Shroud.Detection;

public static class LuhnValidator
{
    public static bool IsValid(string input)
    {
        var digits = new List<int>();
        foreach (var c in input)
        {
            if (char.IsDigit(c))
                digits.Add(c - '0');
            // Skip spaces and dashes (common in card formatting)
        }

        if (digits.Count < 13 || digits.Count > 19)
            return false;

        var sum = 0;
        var alternate = false;
        for (var i = digits.Count - 1; i >= 0; i--)
        {
            var d = digits[i];
            if (alternate)
            {
                d *= 2;
                if (d > 9)
                    d -= 9;
            }
            sum += d;
            alternate = !alternate;
        }

        return sum % 10 == 0;
    }
}
