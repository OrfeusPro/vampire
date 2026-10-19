using System.Security.Cryptography;
using System.Text.Json;
using CUE4Parse.UE4.Pak;
using CUE4Parse.UE4.Versions;
using CUE4Parse.UE4.Readers;
using CUE4Parse.UE4.Objects.UObject;

// Read-only, one archive. Explicit profile is a test input, not engine detection.
if (args.Length != 3)
    throw new ArgumentException("Usage: Cue4ParseProbe <pak-or-uasset> <EGame profile> <report.json>");
var source = Path.GetFullPath(args[0]);
var profile = Enum.Parse<EGame>(args[1]);
var rows = new List<object>();
string? error = null;
int? count = null;
int? version = null;
bool? encrypted = null;
object? summary = null;
try
{
    if (Path.GetExtension(source).Equals(".uasset", StringComparison.OrdinalIgnoreCase))
    {
        using var archive = new FStreamArchive(source, File.OpenRead(source), new VersionContainer(profile));
        var header = new FPackageFileSummary(archive);
        summary = new { header.Tag, header.TotalHeaderSize, header.NameCount, header.NameOffset,
            header.ExportCount, header.ImportCount, header.bUnversioned, consumed = archive.Position };
    }
    else
    {
        using var reader = new PakFileReader(source, new VersionContainer(profile));
        version = (int)reader.Info.Version;
        encrypted = reader.IsEncrypted;
        if (reader.IsEncrypted) throw new InvalidOperationException("Encrypted index: no keys supplied by probe");
        reader.Mount(StringComparer.OrdinalIgnoreCase);
        count = reader.Files.Count;
        foreach (var entry in reader.Files.Values.OrderBy(x => x.Path).Take(8))
        {
            // Never dump bulk game data; a bounded read proves extraction separately from mounting.
            if (entry.Size > 1024 * 1024 || entry.IsEncrypted) continue;
            try
            {
                var bytes = entry.Read();
                rows.Add(new { path = entry.Path, size = bytes.Length,
                    sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)) });
            }
            catch (Exception ex) { rows.Add(new { path = entry.Path, error = ex.GetType().Name, message = ex.Message }); }
        }
    }
}
catch (Exception ex) { error = ex.ToString(); }
using var input = File.OpenRead(source);
var result = new { source, source_sha256 = Convert.ToHexStringLower(SHA256.HashData(input)),
    package = "CUE4Parse 1.2.2.202610", profile = profile.ToString(), version, encrypted,
    count, samples = rows, summary, error,
    scope = "PAK mount/extraction or loose package header only; UObject properties not tested" };
File.WriteAllText(args[2], JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine(JsonSerializer.Serialize(new { count, samples = rows.Count, error }));
return error is null ? 0 : 2;
