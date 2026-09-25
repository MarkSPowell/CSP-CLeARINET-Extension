using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Clearinet.CompatShim;

[assembly: RequiredVersion("2.4.9.3")]
namespace ClearinetCSP
{
    public class CspExtension : IAutoTamper3, IDisposable
    {
        public static class Settings
        {
            private const string prefix = "ClearinetCSP.";
            public static bool verboseLogging
            {
                get { return FiddlerApplication.Prefs.GetBoolPref(prefix + "verboseLogging", false); }
                set { FiddlerApplication.Prefs.SetBoolPref(prefix + "verboseLogging", value); }
            }
            public static bool enabled
            {
                get { return FiddlerApplication.Prefs.GetBoolPref(prefix + "enabled", false); }
                set { FiddlerApplication.Prefs.SetBoolPref(prefix + "enabled", value); }
            }
        }

        public class HostLogger : ILogger
        {
            public void Log(string message)
            {
                if (Settings.verboseLogging)
                {
                    FiddlerApplication.Log.LogString("CLeARINET CSP: " + message);
                }
            }
        }

        public static string reportHost = "fiddlercsp.deletethis.net";
        private ILogger logger;
        private CSPRuleCollector collector;

        public CspExtension()
        {
            logger = new HostLogger();
            collector = new CSPRuleCollector(logger);
        }

        public void OnPeekAtRequestHeaders(Session oSession) { }
        public void OnPeekAtResponseHeaders(Session oSession) { }
        public void AutoTamperRequestAfter(Session oSession) { }

        public void AutoTamperRequestBefore(Session session)
        {
            if (!Settings.enabled) return;

            if (!session.HostnameIs(reportHost) || session.isFTP) return;

            // TODO: We should offer an option to hide the reports from the session list; change "ui-strikeout" to "ui-hide" in the next line
            session["ui-strikeout"] = "CSPReportGenerator";

            if (session.HTTPMethodIs("CONNECT"))
            {
                session["x-replywithtunnel"] = "CSPReportGenerator";
                return;
            }

            session.utilCreateResponseAndBypassServer();
            session.oResponse.headers.Add("Content-Type", "text/html");
            session.ResponseBody = Encoding.UTF8.GetBytes("<!doctype html><HTML><BODY><H1>Report received. Thanks. You're the best.</H1></BODY></HTML>");

            string requestBody = session.GetRequestBodyAsString();
            if (requestBody.Length > 0)
            {
                try
                {
                    CSPReport cspReport = CSPReport.Parse(requestBody);
                    if (cspReport.cspReport != null && cspReport.cspReport.documentUri != null)
                    {
                        logger.Log("Got report for " + cspReport.cspReport.documentUri + " via " + session.fullUrl);
                    }

                    logger.Log("Adding " + cspReport.ToString());
                    collector.Add(cspReport, session.PathAndQuery == "/unsafe-eval" ?
                        CSPRuleCollector.InterpretBlank.UnsafeEval : CSPRuleCollector.InterpretBlank.UnsafeInline);
                    logger.Log("Total " + collector.ToString());
                }
                catch (Exception exception)
                {
                    logger.Log("Invalid CSP - " + exception);
                }
            }
        }

        public void AutoTamperResponseAfter(Session oSession) { }

        public void AutoTamperResponseBefore(Session session)
        {
            if (!Settings.enabled) return;

            if (!session.isTunnel && !session.isFTP)
            {
                // Use https report URI for https sites because otherwise Chrome won't report.
                // Use http report URI for http sites because the proxy might not be decrypting https.
                string reportUri = (session.isHTTPS ? "https" : "http") + "://" + reportHost;
                // child-src generates a complaint in FireFox as apparently it isn't implemented.
                string CSPROCommon = "child-src 'none'; connect-src 'none'; font-src 'none'; frame-src 'none'; img-src 'none'; media-src 'none'; object-src 'none'; style-src 'none'; ";
                // Two different CSP-Report-Only headers with different report URIs so that we can tell the difference between unsafe-eval and unsafe-inline since they're
                // both reported as empty string blocked-uri properties. Sort of a CSP spec problem.
                session.oResponse.headers.Add("Content-Security-Policy-Report-Only", CSPROCommon + "script-src 'unsafe-eval'; report-uri " + reportUri + "/unsafe-inline");
                session.oResponse.headers.Add("Content-Security-Policy-Report-Only", "script-src 'unsafe-inline'; report-uri " + reportUri + "/unsafe-eval");
                session.oResponse.headers.Add("X-Modified-By", "CLeARINET CSP Rule Collector");

                // Set cache headers to not cache response since we're modifying the headers and don't want browsers to remember this.
                session.oResponse.headers.Remove("Cache-Control");
                session.oResponse.headers.Add("Cache-Control", "private, max-age=0, no-cache");
                session.oResponse.headers.Remove("Expires");
                session.oResponse.headers.Add("Expires", "Thu, 01 Dec 1983 20:00:00 GMT");

                logger.Log("Adding report-only to " + session.fullUrl);
            }
        }

        public void OnBeforeReturningError(Session oSession) { }

        public void OnBeforeUnload() { }

        public void OnLoad()
        {
            AddTab();
        }

        private void AddTab()
        {
            // CLeARINET's own API for an extension's tab; the view is Avalonia.
            Clearinet.Compatibility.Extensions.ExtensionUi.AddTab("CSP Rule Collector", new RuleCollectionView(collector));
        }

        private void Dispose(bool managedAndNative)
        {
            collector.Dispose();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
