# SScompare_hashes
Compare hashes found with Sysmon+SIEM to hashes found in VirusShare repository

This script was developed for use with QRadar SIEM and RedHat OS, so you may need to make some adjustments to use it with other SIEMs. The core idea remains the same, and adapting it shouldn't be too difficult. Perhaps ChatGPT could help you with the adaptation. The only QRadar-specific part of the code is commented. Good Luck! ;)

To use this, first you will need to generate some data for the script to ingest. I used QRadar's Report function to create a CSV file containing the hashes I wanted to check for maliciousness. Then, you will need the VirusShare (.md5) files from virusshare.com. Finally, the script will do the hard work and send the results to the FIFO file.

Next, you'll need to determine how to forward the FIFO data back to the SIEM. I used syslog-ng with a custom configuration, which is also available here. Once the events start arriving in the SIEM, you can process them as needed!
