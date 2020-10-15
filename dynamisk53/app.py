import logging
import re
import base64
import ipaddress

import boto3
import botocore.exceptions

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class DynDNS2Exception(Exception):
    pass


def find_hosted_zone_id_from_hostname(route53, hostname):
    hostname = _normalize_hostname(hostname)

    response = route53.list_hosted_zones()

    if response["IsTruncated"]:
        log.warning("Does not currently support AWS accounts with more than 100 hosted zones due to not implementing"
                    "pagination for 'list_hosted_zones'.")

    hosted_zones = response["HostedZones"]
    hosted_zone = next(iter([hosted_zone for hosted_zone in hosted_zones if hostname.endswith(hosted_zone["Name"])]),
                       None)
    if hosted_zone:
        return hosted_zone["Id"].split("/")[-1]
    else:
        return None


def dyndns2_update_hostname(route53, hosted_zone_id, hostname, new_ip):
    # current_ip = None

    rr_set = route53.list_resource_record_sets(
        HostedZoneId=hosted_zone_id,
        StartRecordName=hostname,
        StartRecordType="A",
        MaxItems="1",
    )

    if len(rr_set["ResourceRecordSets"]) > 1:
        log.error(f"Multiple resource record sets found for: {hostname}.")
        raise DynDNS2Exception("servererror")

    record = rr_set["ResourceRecordSets"][0]

    if record["Name"] == hostname and record["Type"] == "A":
        if len(record["ResourceRecords"]) == 1:
            current_ip = record["ResourceRecords"][0]["Value"]
        else:
            log.error(f"Multiple resource records found for: {hostname}.")
            raise DynDNS2Exception("servererror")
    else:
        log.error(f"Can´t find resource records for {hostname} {record['Type']}.")
        raise DynDNS2Exception("nohost")

    if current_ip == new_ip:
        log.info(f"No change in {hostname} with IP {current_ip}. Not updating.")
        return f"nochg {current_ip}"

    route53.change_resource_record_sets(
        HostedZoneId=hosted_zone_id,
        ChangeBatch={
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": hostname,
                        "Type": "A",
                        "TTL": 60,
                        "ResourceRecords": [
                            {
                                "Value": new_ip,
                            }
                        ],
                    },
                },
            ]
        },
    )

    log.info(f"Successfully updated {hostname} from {current_ip} to {new_ip}.")
    return f"good {new_ip}"


def _normalize_hostname(hostname):
    if not hostname.endswith("."):
        return f"{hostname}."
    else:
        return hostname


def _parse_basic_auth(basic_auth):
    encoded = re.match('^Basic (.*)$', basic_auth)[1]
    pair = base64.b64decode(encoded)
    first, second = pair.split(b':')

    return first.decode(), second.decode()


def _validate_ip(ip):
    try:
        ipaddress.IPv4Address(ip)
        return ip
    except ipaddress.AddressValueError:
        log.error(f"Invalid IP: {ip}")
        raise DynDNS2Exception("badagent")


def _create_route53_client(access_key_id, access_secret_key):
    boto3.set_stream_logger('')
    return boto3.client(
        "route53",
        aws_access_key_id=access_key_id,
        aws_secret_access_key=access_secret_key,
    )


def _dyndns2_handler(event, _context):
    try:
        hostname = _normalize_hostname(event["queryStringParameters"]["hostname"])
        myip = _validate_ip(event["queryStringParameters"]["myip"])
        access_key_id, access_secret_key = _parse_basic_auth(event["headers"]["Authorization"])

        route53 = _create_route53_client(access_key_id, access_secret_key)

        hosted_zone_id = find_hosted_zone_id_from_hostname(route53, hostname)
        if not hosted_zone_id:
            log.error(f"Can´t find matching HostedZoneId for hostname: {hostname}.")
            raise DynDNS2Exception("nohost")

        return dyndns2_update_hostname(route53, hosted_zone_id, hostname, myip)
    except botocore.exceptions.ClientError:
        log.exception("Error communicating with AWS Route53:")
        raise DynDNS2Exception("badauth")


def lambda_handler(event, context):
    # noinspection PyBroadException
    try:
        dyndns2_answer = _dyndns2_handler(event, context)
        status_code = 200
    except DynDNS2Exception as e:
        dyndns2_answer = e.args[0]
        status_code = 500
    except Exception:
        log.exception("Got unhandled exception from _dyndns2_handler:")
        dyndns2_answer = "911"
        status_code = 500

    return {
        "statusCode": status_code,
        "body": f"{dyndns2_answer}\n",
        "headers": {
            "Content-Type": "text/plain",
        },
    }
