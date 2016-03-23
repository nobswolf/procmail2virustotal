# Introduction #

A Python script intended to get used as a ProcMail-filter. It creates MD5-hashes for each MIME-part in the email and checks them against the API of VirusTotal.

It adds some header-fields that can be used for following ProcMail-filtering


# Details #

  * MailHeader **X-Virus-Flag**
    * **Yes** means at least one scanner reports a _positive_ for one of the MIME-parts
    * **None Found** means no positives have been found for this email

  * MailHeader **X-Virus-String** entries for each MIME-part separated by #
    * **untested** one part is not known to any of the scanners
    * **no response** most likely because the API was overloaded
    * **not checked** harmless MIME-Types like _text/plain_ are skipped
    * **`<positives>`/`<total>`** number of reported positives and total number of scanners

# Setup #

  * get your account and API-key from VirusTotal
  * setup your ProcMail to use procmail2virustotal as a filter
  * add a ProcMail filter after that to handle recognized malware

# Recommendations #

  * use GreyListing as a first line of defense. It effectively blocks those brainless spam-zombies
  * use SpamAssassin as second line.
  * filter all recognized spam away
  * procmail2virustotal is the third line
  * use X-Virus-Flag to filter recognized malware away
  * you should have an almost clean inbox here
  * all other measures come here

# more info #

There are lots of ways to get configure all that stuff. The recommendations above describe my configuration. I run a PostFix on my personal Internet-server. So the amount of emails is quite low. Consider buying a full license at VirusTotal if you need a higher rate of checks.

Another measure against unwanted email is a blacklist as first line of defense. Those are difficult to maintain. If you are not willing to continuously updating it you should forget this idea. Better use free online services as part of SpamAssassin then.

The filtering for malware with this script (and malware scanners in general) is **not** a guarantee to be save from malware. This script is more likely considering malware as a part of the Spam to keep the in-box clean. The most simple rule to avoid the threat is: Never-ever running an executable you got in an attachment. No company will send you an invoice, an offer or what-ever as an EXE. And switch off this &%$§%%