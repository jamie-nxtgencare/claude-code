#!/bin/bash
set -euo pipefail  # Exit on error, undefined vars, and pipeline failures
IFS=$'\n\t'       # Stricter word splitting

# Flush existing rules and delete existing ipsets
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
ipset destroy allowed-domains 2>/dev/null || true

# First allow DNS and localhost before any restrictions
# Allow outbound DNS
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
# Allow inbound DNS responses
iptables -A INPUT -p udp --sport 53 -j ACCEPT
# Allow outbound SSH
iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
# Allow inbound SSH responses
iptables -A INPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT
# Allow localhost
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Create ipset with CIDR support
ipset create allowed-domains hash:net

# Fetch GitHub meta information and aggregate + add their IP ranges
echo "Fetching GitHub IP ranges..."
gh_ranges=$(curl -s https://api.github.com/meta)
if [ -z "$gh_ranges" ]; then
    echo "ERROR: Failed to fetch GitHub IP ranges"
    exit 1
fi

if ! echo "$gh_ranges" | jq -e '.web and .api and .git' >/dev/null; then
    echo "ERROR: GitHub API response missing required fields"
    exit 1
fi

echo "Processing GitHub IPs..."
while read -r cidr; do
    if [[ ! "$cidr" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        echo "ERROR: Invalid CIDR range from GitHub meta: $cidr"
        exit 1
    fi
    echo "Adding GitHub range $cidr"
    ipset add allowed-domains "$cidr"
done < <(echo "$gh_ranges" | jq -r '(.web + .api + .git)[]' | aggregate -q)

# Resolve and add other allowed domains
for domain in \
    "registry.npmjs.org" \
    "api.anthropic.com" \
    "sentry.io" \
    "statsig.anthropic.com" \
    "statsig.com" \
    "pub.dev" \
    "api.pub.dev" \
    "pub.dartlang.org" \
    "storage.googleapis.com" \
    "*.googleapis.com" \
    "googleapis.com" \
    "fonts.googleapis.com" \
    "fonts.gstatic.com" \
    "dart.dev" \
    "flutter.dev" \
    "dartlang.org" \
    "oauth2.googleapis.com" \
    "accounts.google.com" \
    "www.googleapis.com" \
    "compute.googleapis.com" \
    "cloudresourcemanager.googleapis.com" \
    "crash-reporting-worker.p.googleapis.com" \
    "dart-services.p.googleapis.com" \
    "maven.google.com" \
    "dl.google.com" \
    "cocoapods.org" \
    "cdn.cocoapods.org"; do
    echo "Resolving $domain..."
    ips=$(dig +short A "$domain")
    if [ -z "$ips" ]; then
        echo "WARNING: Failed to resolve $domain, skipping..."
        continue
    fi

    while read -r ip; do
        if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            echo "WARNING: Invalid IP from DNS for $domain: $ip, skipping..."
            continue
        fi
        echo "Adding $ip for $domain"
        ipset add allowed-domains "$ip"
    done < <(echo "$ips")
done

# Add Google Cloud Storage IP ranges for Flutter dependencies
echo "Adding Google Cloud Storage ranges for Flutter..."
# These are common Google Cloud Storage IP ranges
for range in \
    "34.64.0.0/11" \
    "34.96.0.0/12" \
    "35.184.0.0/13" \
    "35.192.0.0/14" \
    "35.196.0.0/15" \
    "35.198.0.0/16" \
    "35.199.0.0/16" \
    "35.200.0.0/13" \
    "35.208.0.0/12" \
    "35.224.0.0/12" \
    "35.240.0.0/13" \
    "108.177.8.0/21" \
    "108.177.96.0/19" \
    "130.211.0.0/16" \
    "162.216.148.0/22" \
    "162.222.176.0/21" \
    "173.255.112.0/20" \
    "199.36.154.0/23" \
    "199.36.156.0/24" \
    "208.68.108.0/23"; do
    echo "Adding Google Cloud range $range"
    ipset add allowed-domains "$range"
done

# Get host IP from default route
HOST_IP=$(ip route | grep default | cut -d" " -f3)
if [ -z "$HOST_IP" ]; then
    echo "ERROR: Failed to detect host IP"
    exit 1
fi

HOST_NETWORK=$(echo "$HOST_IP" | sed "s/\.[0-9]*$/.0\/24/")
echo "Host network detected as: $HOST_NETWORK"

# Set up remaining iptables rules
iptables -A INPUT -s "$HOST_NETWORK" -j ACCEPT
iptables -A OUTPUT -d "$HOST_NETWORK" -j ACCEPT

# Set default policies to DROP first
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# First allow established connections for already approved traffic
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Then allow only specific outbound traffic to allowed domains
iptables -A OUTPUT -m set --match-set allowed-domains dst -j ACCEPT

echo "Firewall configuration complete"
echo "Verifying firewall rules..."
if curl --connect-timeout 5 https://example.com >/dev/null 2>&1; then
    echo "ERROR: Firewall verification failed - was able to reach https://example.com"
    exit 1
else
    echo "Firewall verification passed - unable to reach https://example.com as expected"
fi

# Verify GitHub API access
if ! curl --connect-timeout 5 https://api.github.com/zen >/dev/null 2>&1; then
    echo "ERROR: Firewall verification failed - unable to reach https://api.github.com"
    exit 1
else
    echo "Firewall verification passed - able to reach https://api.github.com as expected"
fi

# Verify Flutter/Dart access
echo "Verifying Flutter/Dart domain access..."
if curl --connect-timeout 5 https://pub.dev >/dev/null 2>&1; then
    echo "Firewall verification passed - able to reach pub.dev for Flutter/Dart packages"
else
    echo "WARNING: Unable to reach pub.dev - Flutter commands may still fail"
fi

# Verify Android dependency access
echo "Verifying Android dependency domain access..."
if curl --connect-timeout 5 https://maven.google.com >/dev/null 2>&1; then
    echo "Firewall verification passed - able to reach maven.google.com for Android dependencies"
else
    echo "WARNING: Unable to reach maven.google.com - Android builds may fail"
fi

# Verify iOS dependency access
echo "Verifying iOS dependency domain access..."
if curl --connect-timeout 5 https://cocoapods.org >/dev/null 2>&1; then
    echo "Firewall verification passed - able to reach cocoapods.org for iOS dependencies"
else
    echo "WARNING: Unable to reach cocoapods.org - iOS builds may fail"
fi
