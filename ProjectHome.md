Real malware-filters are slow and ressource-hungry. But most viruses come in "waves". So when a virus reaches a specific mail-server it might be already known. So there is no need for a full scan.

This Python-script uses MD5-hashes to recognize already well known viruses. It is meant to be included as a filter in ProcMail and then checks the MD5 against the VirusTotal-API