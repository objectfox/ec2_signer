#!/usr/bin/env perl

use Digest;
use Digest::SHA qw(hmac_sha256_base64);
use URI::Escape qw(uri_escape_utf8);

# Print the docs if no arguments are supplied.

print_docs();

# Set our environment variables.

if ($ENV{'EC2_ACCESS_KEY'}) {
	$EC2_ACCESS_KEY = $ENV{'EC2_ACCESS_KEY'};
} else {
	die "EC2_ACCESS_KEY environment variable must be set.";
};

if ($ENV{'EC2_SECRET_KEY'}) {
	$EC2_SECRET_KEY = $ENV{'EC2_SECRET_KEY'};
} else {
	die "EC2_SECRET_KEY environment variable must be set.";
};

if ($ENV{'EC2_URL'}) {
	$EC2_URL = $ENV{'EC2_URL'};
} else {
	die "EC2_URL environment variable must be set.";
};

# Pull the host and path out of EC2_URL, since we need them for signing.

if ($EC2_URL =~ /\/\/([^\/]+)(.*)$/) {
	$EC2_HOST = $1;
	if ($2) {
		$EC2_PATH = $2;
	} else {
		$EC2_PATH = "/";
	};
};

# Check to see if we have -r or -p, shove everything else into the actions list.

foreach $arg (@ARGV) {
	if ($arg eq "-p") {
		$pretty = 1;
	} elsif ($arg eq "-r") {
		$request = 1;
	} else {
		push (@actions, $arg);
	};
};

# Generate our timestamp for request signing.

$timestamp = generate_timestamp();

# Add the required variables to complete request signing to the actions list.
# In the future we should let the user override.

push (@actions, "SignatureMethod=HmacSHA256", "SignatureVersion=2",
                "Version=2011-05-15", "AWSAccessKeyId=$EC2_ACCESS_KEY",
                "Timestamp=$timestamp");

# Process the actions list to escape bad characters in names and values.

foreach $action (@actions) {
	($x,$y) = split(/\=/,$action,2);
	$x = uri_escape_utf8($x);
	$y = uri_escape_utf8($y);
	push (@clean_actions,"$x=$y");
};

# Sort them for signing purposes.

@clean_actions = sort(@clean_actions);

# Create the query string for signing.

$query = join ("&", @clean_actions);

# Sign the query string.

$sig = uri_escape_utf8(hmac_sha256_base64("GET\n$EC2_HOST\n$EC2_PATH\n$query",
                       $EC2_SECRET_KEY));

# Add the signature to the end of the request url.

push (@clean_actions,"Signature=$sig=");

# Re-create the query string with the signature included.

$query = join ("&", @clean_actions);

if ($request) {

# If we're making a request, print out the request in an attractive manner.
	
	print "Command\n-------\ncurl \"$EC2_URL?$query\"\n\nResponse\n--------\n";

# If we're pretty printing, pipe the output through xmllint, otherwise just
# dump the curl output.

	if ($pretty) {
		$resp = `curl -s \"$EC2_URL?$query\" 2>&1 | xmllint --format -`;
	} else {
		$resp = `curl -s \"$EC2_URL?$query\" 2>&1`;
	};
	print $resp."\n";

} else {

# No request to make, just spit out the signed url.
	
	print "$EC2_URL?$query\n";

};

sub generate_timestamp {

# EC2 compatible timestamp creation.

    return sprintf("%04d-%02d-%02dT%02d:%02d:%02d.000Z",
       sub {    ($_[5]+1900,$_[4]+1,$_[3],$_[2],$_[1],$_[0])
           }->(gmtime(time)));
}

sub print_docs {
	if (!($ARGV[0])) {
		print <<EOT;
ec2_signer.pl Action=Task Option=Value

Options:

	-r to make the request with curl and print the response
	-p to pretty print the XML response with xmllint

Examples:

	Add a KeyPair named mykeypair:
	ec2_signer.pl Action=CreateKeyPair KeyName=newkeypair
	
	List Instances:
	ec2_signer.pl Action=DescribeInstances

	Associate Address with Instance:
	ec2_signer.pl Action=AssociateAddress PublicIp=1.1.1.1 InstanceId=xyz

Note:

	EC2_ACCESS_KEY, EC2_SECRET_KEY and EC2_URL environment variables
	must be set.
EOT
		exit;
	};
};
