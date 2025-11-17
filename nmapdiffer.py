#!/usr/bin/python3

import sys, os, filecmp, datetime, getopt, pathlib, json, urllib.request

USAGE = """Usage: nmapdiff.py -f <nmap flags> -i <target IP or host(s)>

Example:
  python nmapdiff.py -f "-sV -p 1-1000" -i "scanme.nmap.org"
"""

# Sends message to slack group to alert of the changes in scan
def _post_to_slack(text: str) -> None:
   """Send a message to Slack using the incoming webhook.

   Using Python's stdlib HTTP client avoids shell / URL quoting issues
   (especially on Windows) that were causing curl errors.
   """
   webhook_url = "https://hooks.slack.com/services/XXXXXXX/XXXXXXX/XXXXXXX
   payload = {
      "channel": "#notifications",
      "username": "alert",
      "text": text,
   }
   data = json.dumps(payload).encode("utf-8")
   req = urllib.request.Request(
      webhook_url,
      data=data,
      headers={"Content-Type": "application/json"},
      method="POST",
   )
   try:
      urllib.request.urlopen(req)
   except Exception as e:
      # Fail silently to avoid breaking scans if Slack is unreachable
      print(f"Warning: failed to send Slack notification: {e}")


def slack(ip, summary: str | None = None):  # add in url from your slack channel
   base_msg = "Nmap Difference discovered. New" # Sends a simple message to Slack when an Nmap scan starts
def slack_scan_started(ip):  # add in url from your slack channel
   now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
   _post_to_slack(f"Nmap scan started for {ip} at {now}")


def build_diff_summary(today_path: pathlib.Path, yesterday_path: pathlib.Path) -> str:
   """Return a short summary of differences between two scan files.

   Lines present only in today's file are treated as *new*; lines present
   only in yesterday's file are treated as *closed*.
   """
   try:
      with open(today_path, "r") as ft:
         today_lines = {line.strip() for line in ft if line.strip()}
      with open(yesterday_path, "r") as fy:
         yesterday_lines = {line.strip() for line in fy if line.strip()}
   except FileNotFoundError:
      return "(Could not read one or both scan files to build summary.)"

   new_lines = sorted(today_lines - yesterday_lines)
   closed_lines = sorted(yesterday_lines - today_lines)

   parts: list[str] = []
   if new_lines:
      parts.append("New findings:\n" + "\n".join(new_lines))
   if closed_lines:
      parts.append("Closed findings:\n" + "\n".join(closed_lines))

   if not parts:
      return "(Files differ but no line-level additions/removals were detected.)"

   return "\n\n".join(parts)

def main(argv):
   #Variables
   today = datetime.date.today()
   yesterday = today - datetime.timedelta(days = 1)
   today = str(today)
   yesterday = str(yesterday)
   flags = ''
   ip = ''
   
   # Define nmap_scans directory and create if it doesn't exist
   script_dir = pathlib.Path(__file__).parent
   nmap_scans_dir = script_dir / 'nmap_scans'
   nmap_scans_dir.mkdir(parents=True, exist_ok=True)
   
   # If no arguments are provided, show usage and exit
   if not argv:
      print(USAGE)
      sys.exit(1)

   #Take in arguments
   try:
      opts, args = getopt.getopt(argv,"hf:i:",["flags=","ip="])
   except getopt.GetoptError:
      print(USAGE)
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         print(USAGE)
         sys.exit()
      elif opt in ("-f", "--flags"):
         flags = arg
      elif opt in ("-i", "--ip"):
         ip = arg
      #Call nmap with args
   gnmap_file = nmap_scans_dir / f'scan_{today}.gnmap'
   txt_file = nmap_scans_dir / f'scan_{today}.txt'
   
   # Notify Slack that the scan has started
   slack_scan_started(ip)

   # Run nmap scan
   os.system(f'nmap {flags} {ip} -oG "{gnmap_file}" > NUL 2>&1')
   
   # Process gnmap file to extract host information (grep equivalent)
   try:
      with open(gnmap_file, 'r') as f_in, open(txt_file, 'w') as f_out:
         for line in f_in:
            if line.startswith("Host:"):
               f_out.write(line)
   except FileNotFoundError:
      print(f"Error: Nmap output file not found: {gnmap_file}")
      sys.exit(1)
   
   # Remove the gnmap file
   if gnmap_file.exists():
      os.remove(gnmap_file)

   #Diff with previous day
   ft = nmap_scans_dir / f'scan_{today}.txt'
   fy = nmap_scans_dir / f'scan_{yesterday}.txt'
   
   #If difference exists send message to slack (poss as seperate function)
   # Ensure both files exist before comparison
   if ft.exists() and fy.exists():
      if filecmp.cmp(ft, fy) == False:
         summary = build_diff_summary(ft, fy)
         slack(ip, summary)
   else:
      print(f"Warning: One or both comparison files not found. Today's scan: {ft.exists()}, Yesterday's scan: {fy.exists()}")
      slack(ip, "(No previous scan available for detailed diff summary.)")

if __name__ == "__main__":
   main(sys.argv[1:])
