#!/usr/bin/python3
from logging import raiseExceptions
import click as click
import logging
import subprocess
import pandas as pd
import matplotlib.pyplot as plt
import os
import io
import base64
from datetime import datetime
from enum import Enum

#from pandas.core.frame import DataFrame
from utils.exceptions import StatusCodeException
from utils.reputation_service_api import reputation_service_api
from utils.securitytrails import securitytrails
from utils.logger import get_logger

class service(Enum):
  url = 'url'
  file = 'file'
  ip = 'ip'

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

@click.command()
@click.option('-stapi', '--securitytrails-api-key', required=True, type=str, help='SecurityTrails API Key')
@click.option('-rapi', '--reputation-api-key', required=True, type=str, help='Reputation Service API Key')
@click.option('-we', '--whois-email', required=False, type=str, help='WHOIS registrar email')
@click.option('-soa', '--soa-email', required=False, type=str, help='DNS SOA record')
@click.option('-md', '--manual-domains', default={}, required=False, type=str, help='Manual dictionary of domains (split by [,])')
@click.option('-c', '--customer', required=True, type=str, help='Customer Name (no spaces)')
@click.option('-dtp', '--dnstwist-path', default='/opt/dnstwist', required=False, type=str, help='DNS Twist path. Defaults to /opt/dnstwist')
@click.option('-v', '--verbose', default=False, is_flag=True, help='More logs and prints the full response')
def main(securitytrails_api_key, reputation_api_key, whois_email, soa_email, manual_domains, customer, dnstwist_path, verbose):
  # Instantiate Logger and logging level (default INFO)
  logger = (get_logger(__name__, logging.DEBUG) if verbose else get_logger(__name__))

  # Check DNS Twist path
  if not os.path.isdir(dnstwist_path):
    print(f"{bcolors.FAIL}[-] DNS Twist directory must be present!{bcolors.ENDC}")
    quit()

  # Default output directory, which is in .gitignore to not sync with SVC
  outpath = 'output'
  
  # Capitalize customer name
  customer = customer.upper()

  # Create directory
  os.makedirs(f'{outpath}/{customer}', exist_ok=True)

  # SecurityTrails.com API Key
  st_api_key = securitytrails_api_key
  # Instantiate securitytrails class and exec test connection to check API key
  st = securitytrails(st_api_key)

  # Pass the CHKP Reputation API Key
  rs_api_key = reputation_api_key

  # Test domains
  #domains = {'heise.de', 'cnet.com'}
  
  # Instantiate domains as dict
  domains = {}
  
  # Check if we have provided any data for lookups
  if whois_email is None and soa_email is None and manual_domains == {}:
    print(f"{bcolors.FAIL}[-] You need to provide WHOIS Registrar email, DNS SOA A record email, or manual domains!{bcolors.ENDC}")
    quit()
  ## Get domains based on WHOIS email address
  rep_whois_domains = {} if whois_email is None else st.domain_searcher('hostname', whois_email=whois_email)
  logger.debug(f"{bcolors.OKGREEN}[+] WHOIS based domains: {rep_whois_domains}{bcolors.ENDC}")
  ## Get domains based on DNS SOA email record
  rep_soa_domains = {} if soa_email is None else st.domain_searcher('hostname', soa_email=soa_email)
  logger.debug(f"{bcolors.OKGREEN}[+] DNS SOA based domains: {rep_soa_domains}{bcolors.ENDC}")
  ## Get domains manually fed in. Split by comma
  manual_domains = {} if manual_domains == {} else manual_domains.split(",")
  logger.debug(f"{bcolors.OKGREEN}[+] Manually fed domains: {manual_domains}{bcolors.ENDC}")

  # TODO: If WHOIS and/or SOA used, and no manual domains provided, AND API usage limit, STOP
  # TODO: Dedupe the DataFrame data
  
  ## Combine two sets
  domains = set(rep_whois_domains).union(rep_soa_domains)
  # Update main domains set with manual domains
  domains.update(manual_domains)
  print(f"{bcolors.OKGREEN}[+] Domains: {domains}{bcolors.ENDC}")

  # Instantiation Dictionary of Domain AND rendered Pandas DataFrame
  dict_domains = {}
  
  # DNS Twist root path
  dt_root = dnstwist_path
  dt_format = 'csv'
  # Generate DNS Twist domains
  for domain in domains:
    if os.path.exists(f"{outpath}/{customer}/{domain}.{dt_format}"):
      print(f"{bcolors.WARNING}[-] Existing output: {bcolors.BOLD}{bcolors.UNDERLINE}{domain}.{dt_format}{bcolors.ENDC}")
    else:
      # Start timer
      timer_start = datetime.now()
      print(f"{bcolors.OKGREEN}[+] Starting DNS Twist for {bcolors.BOLD}{bcolors.UNDERLINE}{domain}{bcolors.ENDC}")
      # Run DNS Twist on domain
      dt_output = subprocess.run([f'{dt_root}/dnstwist.py', '--all', f'--format={dt_format}', '--geoip', \
        '--mxcheck', f'--output={outpath}/{customer}/{domain}.{dt_format}', '--registered', '--threads=15', '--whois', \
          f'--tld={dt_root}/dictionaries/abused_tlds.dict', f'{domain}'])
      # Stop timer
      timer_stop = datetime.now()
      print(f"{bcolors.OKGREEN}[+]\tRuntime: {timer_stop - timer_start}")
      logging.debug(f"{bcolors.OKBLUE}[+] DNS Twist:\n{dt_output}{bcolors.ENDC}")

    # Parse Pandas DataFrame from CSV, and enrich data with TIS
    df = parse_dataframe(outpath, customer, domain, dt_format, rs_api_key, verbose)
    # Instantiate new dictionary for domain
    dict_domains[domain] = {}
    # Get unfiltered DataFrame into domain's dictionary
    dict_domains[domain]['df'] = df
    # Get HTML from the filtered DataFrame into domain's dictionary
    dict_domains[domain]['html'] = df.to_html(index=False)
    # Write DataFrame to OS in HTML
    df.to_html(f"{outpath}/{customer}/{domain}.html", index=False)
    print(f"{bcolors.OKGREEN}[+]\tWrote HTML in: {outpath}/{customer}/{domain}.html{bcolors.ENDC}")
  
  html_head = """
  <html>
    <head>
      <style>
        h3 { display: inline; }
        table, th, td { font-size:10pt; border:1px solid black; border-collapse:collapse; text-align:left; }
  	    th, td { padding: 1px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
      </style>
    </head>
    <body>
  """

  html_foot = """
    </body>
  </html>
  """

  # Combine all DataFrames into one
  all_df = pd.concat([value['df'] for key, value in dict_domains.items()])
  # Sort by Risk and domain-name
  all_df.sort_values(by=['Risk', 'domain-name'], ascending=False, inplace=True)
  # Filter out Original* and original* our of the DataFrame
  flt_all_df = all_df.loc[~(all_df['fuzzer'].str.contains('riginal'))]
  # Pass the DataFrame and get a base64 encoded picture
  encoded_pic = get_chart(flt_all_df)
  # Create HTML code with base64 encoded picture
  html_pic = '<img src="data:image/png;base64, {}">'.format(encoded_pic.decode('utf-8'))
  # Main HTML file name
  html_file = 'index.html'
  print(f"{bcolors.OKGREEN}[+] Writing final report to: {outpath}/{customer}/{html_file}{bcolors.ENDC}")

  # Delete the main {html_file} file if exists
  if os.path.exists(f"{outpath}/{customer}/{html_file}"):
    os.remove(f"{outpath}/{customer}/{html_file}")

  # Create main HTML file and combine all DataFrames
  with open(f"{outpath}/{customer}/{html_file}", "w") as file:
    file.write(html_head)
    file.write(html_pic)
    file.write("<br>")
    file.write(f"<h3>Top Suspicious Domains:</h3>")
    file.write(flt_all_df.to_html(index=False))
    for domain, item in dict_domains.items():
      file.write("<br>")
      file.write(f"<h3>Domain: {domain}</h3>")
      file.write(item['html'])
    file.write(html_foot)

  print(f"{bcolors.OKGREEN}[+] All done! Find all related files in {outpath}/{customer} directory{bcolors.ENDC}")

def parse_dataframe(outpath, customer, domain, file_type, rs_api_key, verbose) -> pd.DataFrame:
  """
  This function will parse the CSV file into DataFrame, enrich with Threat Intelligence data,
  filter out Benign findings except the original domain, and return Pandas DataFrame back
  """
  print(f"{bcolors.OKGREEN}[+] Working on: {domain}{bcolors.ENDC}")
  a = pd.read_csv(f"{outpath}/{customer}/{domain}.{file_type}", \
    usecols=['fuzzer', 'domain-name', 'dns-a', 'dns-mx','geoip-country'], engine='python')
  a.dropna(subset=['domain-name'], inplace=True)
  a.insert(2,'Severity','')
  a.insert(3,'Risk','')
  a.insert(4,'Classification','')
  a.insert(5,'Confidence','')
  # Loop through Pandas DataFrame for Threat Intelligence
  # Instantiate Reputation Service API and get a token per domain
  threat = reputation_service_api(rs_api_key, verbose)
  for idx, row in a.iterrows():
    print(f"{bcolors.OKGREEN}[+]\tThreat Intelligence on: {a.loc[idx, 'domain-name']}{bcolors.ENDC}")
    res_domain_threat = threat.query(service.url.name, a.loc[idx, 'domain-name'])
    # Split ; as [SPACE] to better render the HTML data as they per default break on [SPACE]
    a.loc[idx, 'dns-mx'] = ' '.join(str(a.loc[idx, 'dns-mx']).split(';'))
    a.loc[idx, 'dns-a'] = ' '.join(str(a.loc[idx, 'dns-a']).split(';'))
    # Loop through Reputation API reponse and assign values to Pandas DataFrame
    if not res_domain_threat is None:
      for key, value in res_domain_threat.items():
        a.loc[idx, key] = value
    
    # This code is for IP Lookups
    #if str(a.loc[idx, 'dns-a']).lower != 'nan':
        #for dns_a in str(a.loc[idx, 'dns-a']).split(';'):
          #print(dns_a)
          #res_ip_threat = threat.query(service.ip.name, dns_a)
          #for key, value in res_ip_threat.items():
          #  print('')
    # This code is for MX Lookups
    #if str(a.loc[idx, 'dns-mx']).lower != 'nan':
        #for dns_mx in str(a.loc[idx, 'dns-mx']).split(';'):
        #  print(dns_mx)
  # Pandas - Sort descending to see highest risk first
  a.sort_values(by=['Risk', 'domain-name'], ascending=False, inplace=True)
  # Pandas - Create two DataFrames. One with Original entry, the other exclude Severity 'N/A' and merge both on return
  tmp1 = a.loc[a['fuzzer'].str.contains('riginal')]
  tmp2 = a.loc[~(a['Severity'].str.contains('N/A'))]
  return pd.concat([tmp1, tmp2])

def get_chart(df :pd.DataFrame) -> bytes:
    # Create a new DataFrame with a groupby on column [Classification] with count column as [count]
    a = df.groupby(['Classification']).size()
    # Instantiate fig and ax for plotting
    fig = None
    ax = None
    fig, ax = plt.subplots()
    # Plot Pie Chart in memory
    a.plot(kind='pie', subplots=True, autopct='%1.1f%%', startangle=90, shadow=False, legend=False, \
      fontsize=10, title='Classifications', ylabel='')
    # Remove Axis lables form the plot
    plt.axis('off')
    img = io.BytesIO()
    fig.savefig(img, format='png', bbox_inches='tight')
    img.seek(0)
    return base64.b64encode(img.getvalue())

if __name__ == '__main__':
  try:
    main()
  except StatusCodeException as e:
    print(e)