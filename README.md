# CSP Rule Collector for CLeARINET

An extension for [CLeARINET](https://github.com/MarkSPowell/CLeARINET) that
works out the smallest set of Content-Security-Policy rules a web page
needs. It runs on Windows and macOS.

This is a CLeARINET-only version of David Risney's
[CSP-Fiddler-Extension](https://github.com/david-risney/CSP-Fiddler-Extension)
(forked from [ericlaw1979/CSP-Fiddler-Extension](https://github.com/ericlaw1979/CSP-Fiddler-Extension)).
**For Fiddler Classic, use the original.**

## Build

This builds against CLeARINET's compatibility layer, so it needs CLeARINET's
source. Clone both repositories side by side:

    GitHub\CLeARINET
    GitHub\CSP-CLeARINET-Extension

then, in this folder:

    dotnet build -c Release

The extension is `bin\Release\net10.0\CLeARINETCSP.dll`. (If CLeARINET is
somewhere else, add `-p:ClearinetRoot=<path to CLeARINET>`.)

`dotnet test` runs the original extension's rule-generation tests.

## Install

Copy `CLeARINETCSP.dll` (only that file) into the CLeARINET extensions folder
and restart CLeARINET:

- Windows: `Documents\CLeARINET\Extensions`
- macOS: `~/Documents/CLeARINET/Extensions`

## Run

- Start CLeARINET's proxy.
- Open the **CSP Rule Collector** tab (next to Inspectors).
- Tick **Enable Rule Collection**.
- Clear your browser's cache, then browse to the page you want rules for.
  CLeARINET intercepts HTTPS only, so use an HTTPS page.
- Select the page's URI in the tab to see its rules.

Don't leave **Enable Rule Collection** on. While it's on, the extension makes
responses non-cacheable and adds CSP headers, which can fill the browser's
developer console with errors.

For accurate results, clear the browser's cache for the site first:
resources served from the cache never pass through CLeARINET, so the
extension can't see them. Visit the site in every browser you care about in
the same CLeARINET session; all browsers' reports are combined into one rule.

## How it works

The extension adds two report-only policies to every response, such as:

    Content-Security-Policy-Report-Only: child-src 'none'; connect-src 'none'; font-src 'none'; frame-src 'none'; img-src 'none'; media-src 'none'; object-src 'none'; style-src 'none'; script-src 'unsafe-eval'; report-uri https://fiddlercsp.deletethis.net/unsafe-inline

The browser reports every violation to the report URI. The extension
answers those report requests itself (they never leave your machine) and
builds the policy from them. The two policies use different report URIs so
inline script and `eval()` can be told apart, since both are reported with an
empty blocked URI.

## Differences from the Fiddler version

- The tab is built with Avalonia instead of WinForms. It has no right-click
  **Copy**; copy from the policy text box instead.
- Names no longer mention Fiddler: the assembly is `CLeARINETCSP`, the
  namespace `ClearinetCSP`, the extension class `CspExtension`, and the
  preferences `ClearinetCSP.enabled` and `ClearinetCSP.verboseLogging`.
  Responses it changes are marked `X-Modified-By: CLeARINET CSP Rule Collector`.
- The report host is unchanged: `fiddlercsp.deletethis.net`.

## License

MIT, as the original. See [LICENSE](LICENSE).
