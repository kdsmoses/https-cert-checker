# Installation

# Clone and cd to git repo:
#	git clone https://github.com/kdsmoses/https-cert-checker.git
#	cd https-cert-checker.git

# If no Python installed (Windows 11 / Server 2025 or newer):
#	winget install --source msstore --id 9NQ7512CXL7T
#	py list --online	# to list available versions
#	py install 3.14		# (or latest version)

# Set up Python virtual environment & install dependencies:
#	cd <script directory>
#	python -m venv .venv
#	pip install dotenv cloudflare slack-sdk

# Usage:
#	copy example.env .env
#	# configure variables in .env file
#	.\check-certs.bat


import os
import sys
import multiprocessing
import ssl
import socket
import datetime
import concurrent.futures
import math

from dotenv import load_dotenv
from cloudflare import Cloudflare
from slack_sdk.webhook import WebhookClient


load_dotenv()  # copy variables from .env file into OS environment variables

# defaults
IGNORE_HOSTS_FILE = os.getenv("IGNORE_HOSTS_FILE")
if not IGNORE_HOSTS_FILE:
	IGNORE_HOSTS_FILE = ".ignore_hosts"
ADDITIONAL_HOSTS_FILE = os.getenv("ADDITIONAL_HOSTS_FILE")
if not ADDITIONAL_HOSTS_FILE:
	ADDITIONAL_HOSTS_FILE = ".additional_hosts"
WARN_IF_DAYS_LESS_THAN = os.getenv("WARN_IF_DAYS_LESS_THAN")
if not WARN_IF_DAYS_LESS_THAN:
	WARN_IF_DAYS_LESS_THAN = 7
else:
	WARN_IF_DAYS_LESS_THAN = int(WARN_IF_DAYS_LESS_THAN)
SOCKET_CONNECTION_TIMEOUT_SECONDS = os.getenv("SOCKET_CONNECTION_TIMEOUT_SECONDS")
if not SOCKET_CONNECTION_TIMEOUT_SECONDS:
	SOCKET_CONNECTION_TIMEOUT_SECONDS = 30
else:
	SOCKET_CONNECTION_TIMEOUT_SECONDS = int(SOCKET_CONNECTION_TIMEOUT_SECONDS)

# optional features
CLOUDFLARE_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
if not CLOUDFLARE_API_TOKEN:
	CLOUDFLARE_API_TOKEN = ""
else:
	cf = Cloudflare(api_token=CLOUDFLARE_API_TOKEN)

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
if not SLACK_WEBHOOK_URL:
	SLACK_WEBHOOK_URL = ""



DEFAULT_HTTPS_PORT = 443

EXIT_SUCCESS = 0
EXIT_EXPIRING_SOON = 1
EXIT_ERROR = 2
EXIT_NO_HOST_LIST = 9

STATUS_WARN = '⚠️'		# WARN
STATUS_OK = '✅'		# OK
STATUS_ERROR = '❌'		# ERROR

WORKER_THREAD_COUNT = multiprocessing.cpu_count() * 2


def make_host_port_pair(endpoint):
	host, _, specified_port = endpoint.partition(':')
	port = int(specified_port or DEFAULT_HTTPS_PORT)

	return host, port


def pluralise(singular, count):
	return '{} {}{}'.format(count, singular, '' if count == 1 else 's')


def get_certificate_expiry_date_time(context, host, port):
	with socket.create_connection((host, port), SOCKET_CONNECTION_TIMEOUT_SECONDS) as tcp_socket:
		with context.wrap_socket(tcp_socket, server_hostname=host) as ssl_socket:
			# certificate_info is a dict with lots of information about the certificate
			certificate_info = ssl_socket.getpeercert()
			exp_date_text = certificate_info['notAfter']
			return datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(exp_date_text), datetime.timezone.utc)


# def format_time_remaining(time_remaining):
# 	day_count = time_remaining.days

# 	if day_count >= WARN_IF_DAYS_LESS_THAN:
# 		return pluralise('day', day_count)

# 	else:
# 		seconds_per_minute = 60
# 		seconds_per_hour = seconds_per_minute * 60
# 		seconds_unaccounted_for = time_remaining.seconds

# 		hours = int(seconds_unaccounted_for / seconds_per_hour)
# 		seconds_unaccounted_for -= hours * seconds_per_hour

# 		minutes = int(seconds_unaccounted_for / seconds_per_minute)

# 		return '{} {} {}'.format(
# 			pluralise('day', day_count),
# 			pluralise('hour', hours),
# 			pluralise('min', minutes)
# 		)


def get_exit_code(err_count, min_days):
	code = EXIT_SUCCESS

	if err_count:
		code += EXIT_ERROR

	if min_days < WARN_IF_DAYS_LESS_THAN:
		code += EXIT_EXPIRING_SOON

	return code


def format_host_port(host, port):
	return host + ('' if port == DEFAULT_HTTPS_PORT else ':{}'.format(port))


def get_cloudflare_zones():
	return cf.zones.list()


def get_cloudflare_dns_records(zone_id):
	return cf.dns.records.list(zone_id=zone_id)





def check_certificates(endpoints):

	if len(endpoints):
		host_port_pairs = [make_host_port_pair(endpoint) for endpoint in endpoints]
	else:
		host_port_pairs = []


	# get hosts to ignore from file
	ignore_hosts = set()
	try:
		with open(os.path.join(os.path.dirname(__file__), IGNORE_HOSTS_FILE), 'r') as fh:
			print(f"Reading ignore directives from {IGNORE_HOSTS_FILE}...")		#, flush=True, end="")
			for line in fh:
				line = line.strip()
				if not line or line.startswith('#'):
					continue
				ignore_hosts.add(line.lower())
			print(f"  {len(ignore_hosts)} hosts added to ignore list.")
	except FileNotFoundError:
		pass


	# get additional domains from file
	try:
		with open(os.path.join(os.path.dirname(__file__), ADDITIONAL_HOSTS_FILE), 'r') as fh:
			print(f"Reading domains from {ADDITIONAL_HOSTS_FILE}...")
			for line in fh:
				line = line.strip()
				if not line or line.startswith('#'):
					continue
				if line.lower() not in ignore_hosts:
					# domains.append([line.lower(), 'A'])
					host_port_pairs.append(make_host_port_pair(line))
			print(f"  Hosts added from file.")
	except FileNotFoundError:
		pass


	# get domains from cloudflare DNS
	if CLOUDFLARE_API_TOKEN != "":
		print(f"Getting Cloudflare DNS zones...")
		zones = get_cloudflare_zones()

		count = sum(1 for _ in zones)
		print(f"Getting Cloudflare DNS records for {count} zones...")

		for z in zones:
			# print(f"Getting domains for {z.name}", flush=True)
			for r in get_cloudflare_dns_records(z.id):
				domain = r.name
				rtype = r.type
				if r.type in ('A', 'CNAME') and domain.lower() not in ignore_hosts and '_domainkey' not in domain.lower():		#, 'AAAA'
					host_port_pairs.append(make_host_port_pair(domain))
					# domains.append([domain, rtype])


	if len(host_port_pairs) == 0:
		print('Usage: {} <list of endpoints>'.format(sys.argv[0]))
		sys.exit(EXIT_NO_HOST_LIST)


	context = ssl.create_default_context()

	results = []

	with concurrent.futures.ThreadPoolExecutor(max_workers=WORKER_THREAD_COUNT) as executor:
		futures = {
			executor.submit(get_certificate_expiry_date_time, context, host, port):
			(host, port) for host, port in host_port_pairs
		}

		endpoint_count = len(host_port_pairs)
		err_count = 0
		warning_count = 0

		min_days = math.inf
		max_host_port_len = max([len(format_host_port(host, port)) for host, port in host_port_pairs])

		print('Checking {}...'.format(pluralise('endpoint', endpoint_count)))
		for future in concurrent.futures.as_completed(futures):
			host, port = futures[future]
			host_and_port = format_host_port(host, port)
			now = datetime.datetime.now(datetime.timezone.utc)
			try:
				expiry_time = future.result()
			except Exception as ex:
				err_count = err_count + 1
				# print('{}  {}  {}'.format(
				# 	'❌',
				# 	host_and_port.ljust(max_host_port_len),
				# 	ex
				# ))
				results.append([None, now, host_and_port, STATUS_ERROR, ex])
			else:
				time_remaining = expiry_time - now
				days_remaining = time_remaining.days
				# time_remaining_txt = f"{time_remaining.days}"		# format_time_remaining(time_remaining)
				min_days = min(min_days, days_remaining)
				# print('{}  {}  {}'.format(
				# 	STATUS_WARN if days_remaining < WARN_IF_DAYS_LESS_THAN else STATUS_OK,
				# 	format_host_port(host, port).ljust(max_host_port_len),
				# 	time_remaining_txt
				# 	))
				if days_remaining < WARN_IF_DAYS_LESS_THAN:
					warning_count = warning_count + 1
					# to only report errors/warnings
					results.append([days_remaining, expiry_time, host_and_port, STATUS_WARN, None])
				# to report all results
				# results.append([days_remaining, expiry_time, host_and_port, STATUS_WARN if days_remaining < WARN_IF_DAYS_LESS_THAN else STATUS_OK, None])


		results_text = f"""
Certificates Check

{'Days'}  {'Expires'.ljust(10)}  {'Host'.ljust(max_host_port_len)}  {'Error'}
{'----'}  {'-'*10}  {'-'*max_host_port_len}  {'-----'}"""
# {'  '}  {'Days'}  {'Expires'.ljust(10)}  {'Host'.ljust(max_host_port_len)}  {'Error'}
# {'--'}  {'----'}  {'-'*10}  {'-'*max_host_port_len}  {'-----'}

	results = sorted(results, key=lambda x: x[1])
	for site in results:
		days, expires, host, status, err = site

		msg = ""
		if days is None:
			days = "-"
			exptext = "[FAIL]"
		else:
			days = str(days)
			# exptext = expires.strftime('%Y-%m-%d %H:%M %Z')		# 24
			exptext = expires.strftime('%Y-%m-%d')

		# if err is None:
		# 	err = ""
		if isinstance(err, BaseException):
			msg = f"{err}"

		results_text = results_text + f"""
{days.rjust(4)}  {exptext.ljust(10)}  {host.ljust(max_host_port_len)}  {msg.ljust(40)}""".rstrip()
# {status.ljust(2)}  {days.rjust(4)}  {exptext.ljust(10)}  {host.ljust(max_host_port_len)}  {err}""".rstrip()
# {status:<2}  {str(days).rjust(4)}  {exptext.ljust(10)}  {host.ljust(max_host_port_len)}  {str(err).ljust(100)}""".rstrip()



	results_text = results_text + f"""

{err_count:3d} check(s) failed.
{warning_count:3d} certificate(s) expire in less than {WARN_IF_DAYS_LESS_THAN} days.
"""


	# print to screen
	print(results_text)


	# send slack alert
	if err_count + warning_count != 0 and SLACK_WEBHOOK_URL != "":
		print("Sending Slack message...")

		webhook = WebhookClient(SLACK_WEBHOOK_URL)
		slack_response = webhook.send(text = f"```{results_text}```")

		assert slack_response.status_code == 200
		assert slack_response.body == "ok"


	exit_code = get_exit_code(err_count, min_days)
	sys.exit(exit_code)


if __name__ == '__main__':
	endpoints = sys.argv[1:]

	# if len(endpoints):
	check_certificates(endpoints=[])
	# else:
		# print('Usage: {} <list of endpoints>'.format(sys.argv[0]))
		# sys.exit(EXIT_NO_HOST_LIST)
