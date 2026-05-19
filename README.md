# TorSharp.Mirror

A long-term binary cache for [TorSharp](https://github.com/joelverhagen/TorSharp).

## What is this?

TorSharp needs Tor and Privoxy binaries at runtime. It normally fetches them from their
respective upstream distribution sites, but those sites can be rate-limited, temporarily
down, or change their URL structure without notice.

This mirror:

- Downloads the latest stable **Tor expert bundles** from
  [dist.torproject.org](https://dist.torproject.org/torbrowser/) for all supported
  platforms (Windows x86/x86_64, Linux x86/x86_64).
- Downloads the latest stable **Privoxy** packages from
  [silvester.org.uk/privoxy](https://www.silvester.org.uk/privoxy/) for
  Windows and Linux (i386, amd64 .deb).
- Verifies every Tor artifact against the **official SHA256 sums** published alongside
  each release at dist.torproject.org.
- Publishes everything as a **GitHub Release** with a signed `manifest.json` that lists
  versions, download URLs, and SHA256 digests.

## Stable manifest URL

```
https://github.com/nefarius/TorSharp.Mirror/releases/latest/download/manifest.json
```

The `TorSharpToolFetcher` uses this URL by default when `TorSharpSettings.UseMirror = true`
(which is the default). If the mirror is unreachable it falls back to the original upstream
scrapers automatically.

## Refresh cadence

The mirror workflow runs **nightly at 03:00 UTC** and on manual dispatch.
Each run creates a new dated GitHub Release (e.g. `mirror-2026.05.19`).
The `/releases/latest/` redirect always points to the most recent non-draft release.

## Schema

The manifest format is described by `manifest.schema.json`, published alongside
`manifest.json` in every release.

Key fields per entry:

| Field        | Type     | Description                                      |
|-------------|----------|--------------------------------------------------|
| `version`   | string   | Dotted version parsable by `System.Version`      |
| `url`       | string   | HTTPS URL of the binary asset                    |
| `sha256`    | string   | Lowercase hex SHA256 of the binary               |
| `format`    | string   | `TarGz`, `Zip`, or `Deb`                         |
| `runtimeDeps` | array  | apt package names required at runtime (Linux only) |

## Self-hosting

You can host your own mirror and point TorSharp at it:

```csharp
var settings = new TorSharpSettings
{
    MirrorManifestUrl = "https://my-internal-mirror.example.com/torsharp/manifest.json"
};
```

The manifest must conform to `manifest.schema.json`.

## Opt out

```csharp
var settings = new TorSharpSettings { UseMirror = false };
```

TorSharp will then fall back to the original upstream discovery logic.
