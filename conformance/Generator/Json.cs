using System.Collections;
using System.Globalization;
using System.Text;

namespace Shroud.Conformance.Generator;

/// <summary>Insertion-ordered JSON object.</summary>
public sealed class O : List<KeyValuePair<string, object?>>
{
    public O P(string key, object? value)
    {
        Add(new KeyValuePair<string, object?>(key, value));
        return this;
    }
}

/// <summary>
/// Minimal deterministic JSON writer: 2-space indent, LF newlines, insertion-ordered objects,
/// doubles in invariant-culture round-trip form ("R"), non-ASCII emitted raw (UTF-8), only the
/// characters that JSON requires are escaped. Arrays of scalars are written on one line.
/// </summary>
public static class Json
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    public static string Write(object? value)
    {
        var sb = new StringBuilder();
        Emit(sb, value, 0);
        sb.Append('\n');
        return sb.ToString();
    }

    public static string Num(double d) => d.ToString("R", Inv);

    private static bool IsScalar(object? v) =>
        v is null or string or bool or int or long or double;

    private static void Indent(StringBuilder sb, int level) => sb.Append(' ', level * 2);

    private static void Emit(StringBuilder sb, object? v, int level)
    {
        switch (v)
        {
            case null: sb.Append("null"); break;
            case bool b: sb.Append(b ? "true" : "false"); break;
            case int i: sb.Append(i.ToString(Inv)); break;
            case long l: sb.Append(l.ToString(Inv)); break;
            case double d: sb.Append(Num(d)); break;
            case string s: Str(sb, s); break;
            case O o:
                if (o.Count == 0) { sb.Append("{}"); break; }
                sb.Append("{\n");
                for (var k = 0; k < o.Count; k++)
                {
                    Indent(sb, level + 1);
                    Str(sb, o[k].Key);
                    sb.Append(": ");
                    Emit(sb, o[k].Value, level + 1);
                    sb.Append(k < o.Count - 1 ? ",\n" : "\n");
                }
                Indent(sb, level);
                sb.Append('}');
                break;
            case IEnumerable e:
                var items = e.Cast<object?>().ToList();
                if (items.Count == 0) { sb.Append("[]"); break; }
                if (items.All(IsScalar))
                {
                    sb.Append('[');
                    for (var k = 0; k < items.Count; k++)
                    {
                        if (k > 0) sb.Append(", ");
                        Emit(sb, items[k], level);
                    }
                    sb.Append(']');
                    break;
                }
                sb.Append("[\n");
                for (var k = 0; k < items.Count; k++)
                {
                    Indent(sb, level + 1);
                    Emit(sb, items[k], level + 1);
                    sb.Append(k < items.Count - 1 ? ",\n" : "\n");
                }
                Indent(sb, level);
                sb.Append(']');
                break;
            default:
                throw new InvalidOperationException("Unsupported JSON value: " + v.GetType());
        }
    }

    private static void Str(StringBuilder sb, string s)
    {
        sb.Append('"');
        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20)
                        sb.Append("\\u").Append(((int)c).ToString("x4", Inv));
                    else if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
                    {
                        sb.Append(c).Append(s[i + 1]);
                        i++;
                    }
                    else if (char.IsSurrogate(c))
                        sb.Append("\\u").Append(((int)c).ToString("x4", Inv)); // lone surrogate
                    else
                        sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }
}
