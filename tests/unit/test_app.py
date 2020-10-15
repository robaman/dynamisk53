import base64
import datetime

import pytest

import botocore.exceptions
import botocore.session
from botocore.stub import Stubber

from dynamisk53 import app

TEST_DOMAIN = "dyndns2.dynamic.tld"
TEST_HOSTNAME = f"host.{TEST_DOMAIN}"
TEST_CALLER_REFERENCE = "CR123"
TEST_HOSTED_ZONE_ID = "HZ123"
TEST_MYIP = "1.2.3.4"


@pytest.fixture()
def apigw_event():
    username = "access-key-id"
    password = "secret-access-key"
    encoded_pair = base64.b64encode(f"{username}:{password}".encode()).decode()
    auth = f"Basic {encoded_pair}"

    return {
        "queryStringParameters": {
            "hostname": TEST_HOSTNAME,
            "myip": TEST_MYIP,
        },
        "headers": {
            "Authorization": auth,
        },
    }


def test_lambda_handler_good(apigw_event, mocker):
    mocker.patch("dynamisk53.app._dyndns2_handler").return_value = "good 1.2.3.4\n"

    response = app.lambda_handler(apigw_event, "")

    assert response["statusCode"] == 200
    assert "good" in response["body"]


def test_lambda_handler_bad(apigw_event, mocker):
    mocker.patch("dynamisk53.app._dyndns2_handler").side_effect = app.DynDNS2Exception("nogood")

    response = app.lambda_handler(apigw_event, "")

    assert response["statusCode"] == 500
    assert "nogood" in response["body"]


def test_lambda_handler_unhandled_exception(apigw_event, mocker):
    mocker.patch("dynamisk53.app._dyndns2_handler").side_effect = Exception("unhandled exception")

    response = app.lambda_handler(apigw_event, "")

    assert response["statusCode"] == 500
    assert "911" in response["body"]


def test_dyndns2_handler_good(apigw_event, mocker):
    route53 = botocore.session.get_session().create_client("route53")
    stubber = Stubber(route53)
    stubber.add_response("list_hosted_zones",
                         {
                             "HostedZones": [{
                                 "Name": f"{TEST_DOMAIN}.",
                                 "Id": f"/hostedzone/{TEST_HOSTED_ZONE_ID}",
                                 "CallerReference": f"{TEST_CALLER_REFERENCE}",

                             }],
                             "MaxItems": "1",
                             "IsTruncated": False,
                             "Marker": "1",
                         },
                         {})
    stubber.add_response("list_resource_record_sets",
                         {
                             "ResourceRecordSets": [
                                 {
                                     "Name": f"{TEST_HOSTNAME}.",
                                     "Type": "A",
                                     "ResourceRecords": [{
                                         "Value": "127.0.0.1",
                                     }],

                                 }
                             ],
                             "IsTruncated": False,
                             "MaxItems": "1",
                         },
                         {
                             "HostedZoneId": TEST_HOSTED_ZONE_ID,
                             "StartRecordName": TEST_HOSTNAME + ".",
                             "StartRecordType": "A",
                             "MaxItems": "1",
                         })
    stubber.add_response("change_resource_record_sets",
                         {"ChangeInfo": {
                             "Id": "",
                             "Status": "",
                             "SubmittedAt": datetime.datetime(2020, 10, 15, 11, 38, 0, 0),
                         }},
                         {
                             "HostedZoneId": f"{TEST_HOSTED_ZONE_ID}",
                             "ChangeBatch": {
                                 "Changes": [
                                     {
                                         "Action": "UPSERT",
                                         "ResourceRecordSet": {
                                             "Name": TEST_HOSTNAME + ".",
                                             "Type": "A",
                                             "TTL": 60,
                                             "ResourceRecords": [
                                                 {
                                                     "Value": "1.2.3.4",
                                                 }
                                             ],
                                         },
                                     }
                                 ],
                             },
                         })
    stubber.activate()
    mocker.patch("dynamisk53.app._create_route53_client").return_value = route53

    response = app._dyndns2_handler(apigw_event, "")

    assert "good" in response


def test_dyndns2_handler_too_many_zones(apigw_event, mocker):
    route53 = botocore.session.get_session().create_client("route53")
    stubber = Stubber(route53)
    stubber.add_response("list_hosted_zones",
                         {
                             "HostedZones": [{
                                 "Name": f"{TEST_DOMAIN}.",
                                 "Id": f"/hostedzone/{TEST_HOSTED_ZONE_ID}",
                                 "CallerReference": f"{TEST_CALLER_REFERENCE}",

                             }],
                             "MaxItems": "1",
                             "IsTruncated": True,
                             "Marker": "1",
                         },
                         {})
    stubber.add_response("list_resource_record_sets",
                         {
                             "ResourceRecordSets": [
                                 {
                                     "Name": f"{TEST_HOSTNAME}.",
                                     "Type": "A",
                                     "ResourceRecords": [{
                                         "Value": "127.0.0.1",
                                     }],

                                 }
                             ],
                             "IsTruncated": False,
                             "MaxItems": "1",
                         },
                         {
                             "HostedZoneId": TEST_HOSTED_ZONE_ID,
                             "StartRecordName": TEST_HOSTNAME + ".",
                             "StartRecordType": "A",
                             "MaxItems": "1",
                         })
    stubber.add_response("change_resource_record_sets",
                         {"ChangeInfo": {
                             "Id": "",
                             "Status": "",
                             "SubmittedAt": datetime.datetime(2020, 10, 15, 11, 38, 0, 0),
                         }},
                         {
                             "HostedZoneId": f"{TEST_HOSTED_ZONE_ID}",
                             "ChangeBatch": {
                                 "Changes": [
                                     {
                                         "Action": "UPSERT",
                                         "ResourceRecordSet": {
                                             "Name": TEST_HOSTNAME + ".",
                                             "Type": "A",
                                             "TTL": 60,
                                             "ResourceRecords": [
                                                 {
                                                     "Value": "1.2.3.4",
                                                 }
                                             ],
                                         },
                                     }
                                 ],
                             },
                         })
    stubber.activate()
    mocker.patch("dynamisk53.app._create_route53_client").return_value = route53

    response = app._dyndns2_handler(apigw_event, "")

    assert "good" in response


def test_dyndns2_handler_no_zone(apigw_event, mocker):
    route53 = botocore.session.get_session().create_client("route53")
    stubber = Stubber(route53)
    stubber.add_response("list_hosted_zones",
                         {
                             "HostedZones": [{
                                 "Name": "non-existing.domain.tld.",
                                 "Id": f"/hostedzone/{TEST_HOSTED_ZONE_ID}",
                                 "CallerReference": f"{TEST_CALLER_REFERENCE}",

                             }],
                             "MaxItems": "1",
                             "IsTruncated": False,
                             "Marker": "1",
                         },
                         {})
    stubber.activate()
    mocker.patch("dynamisk53.app._create_route53_client").return_value = route53

    with pytest.raises(app.DynDNS2Exception, match=r"nohost"):
        app._dyndns2_handler(apigw_event, "")


def test_dyndns2_handler_client_error(apigw_event, mocker):
    route53 = botocore.session.get_session().create_client("route53")
    stubber = Stubber(route53)
    stubber.add_client_error("list_hosted_zones")

    stubber.activate()
    mocker.patch("dynamisk53.app._create_route53_client").return_value = route53

    with pytest.raises(app.DynDNS2Exception, match=r"badauth"):
        app._dyndns2_handler(apigw_event, "")


def test_dyndns2_handler_multiple_rrs(apigw_event, mocker):
    route53 = botocore.session.get_session().create_client("route53")
    stubber = Stubber(route53)
    stubber.add_response("list_hosted_zones",
                         {
                             "HostedZones": [{
                                 "Name": f"{TEST_DOMAIN}.",
                                 "Id": f"/hostedzone/{TEST_HOSTED_ZONE_ID}",
                                 "CallerReference": f"{TEST_CALLER_REFERENCE}",

                             }],
                             "MaxItems": "1",
                             "IsTruncated": False,
                             "Marker": "1",
                         },
                         {})
    stubber.add_response("list_resource_record_sets",
                         {
                             "ResourceRecordSets": [
                                 {
                                     "Name": f"{TEST_HOSTNAME}.",
                                     "Type": "A",
                                     "ResourceRecords": [{
                                         "Value": "127.0.0.1",
                                     }],

                                 },
                                 {
                                     "Name": f"{TEST_HOSTNAME}-duplicate.",
                                     "Type": "A",
                                     "ResourceRecords": [{
                                         "Value": "127.0.0.1",
                                     }],

                                 },
                             ],
                             "IsTruncated": False,
                             "MaxItems": "1",
                         },
                         {
                             "HostedZoneId": TEST_HOSTED_ZONE_ID,
                             "StartRecordName": TEST_HOSTNAME + ".",
                             "StartRecordType": "A",
                             "MaxItems": "1",
                         })

    stubber.activate()
    mocker.patch("dynamisk53.app._create_route53_client").return_value = route53

    with pytest.raises(app.DynDNS2Exception, match=r"servererror"):
        app._dyndns2_handler(apigw_event, "")


def test_dyndns2_handler_multiple_rr_sets(apigw_event, mocker):
    route53 = botocore.session.get_session().create_client("route53")
    stubber = Stubber(route53)
    stubber.add_response("list_hosted_zones",
                         {
                             "HostedZones": [{
                                 "Name": f"{TEST_DOMAIN}.",
                                 "Id": f"/hostedzone/{TEST_HOSTED_ZONE_ID}",
                                 "CallerReference": f"{TEST_CALLER_REFERENCE}",

                             }],
                             "MaxItems": "1",
                             "IsTruncated": False,
                             "Marker": "1",
                         },
                         {})
    stubber.add_response("list_resource_record_sets",
                         {
                             "ResourceRecordSets": [
                                 {
                                     "Name": f"{TEST_HOSTNAME}.",
                                     "Type": "A",
                                     "ResourceRecords": [
                                         {"Value": "127.0.0.1"},
                                         {"Value": "127.0.0.2"}
                                     ],
                                 },
                             ],
                             "IsTruncated": False,
                             "MaxItems": "1",
                         },
                         {
                             "HostedZoneId": TEST_HOSTED_ZONE_ID,
                             "StartRecordName": TEST_HOSTNAME + ".",
                             "StartRecordType": "A",
                             "MaxItems": "1",
                         })

    stubber.activate()
    mocker.patch("dynamisk53.app._create_route53_client").return_value = route53

    with pytest.raises(app.DynDNS2Exception, match=r"servererror"):
        app._dyndns2_handler(apigw_event, "")


def test_dyndns2_handler_invalid_rr_type(apigw_event, mocker):
    route53 = botocore.session.get_session().create_client("route53")
    stubber = Stubber(route53)
    stubber.add_response("list_hosted_zones",
                         {
                             "HostedZones": [{
                                 "Name": f"{TEST_DOMAIN}.",
                                 "Id": f"/hostedzone/{TEST_HOSTED_ZONE_ID}",
                                 "CallerReference": f"{TEST_CALLER_REFERENCE}",

                             }],
                             "MaxItems": "1",
                             "IsTruncated": False,
                             "Marker": "1",
                         },
                         {})
    stubber.add_response("list_resource_record_sets",
                         {
                             "ResourceRecordSets": [
                                 {
                                     "Name": f"{TEST_HOSTNAME}.",
                                     "Type": "MX",
                                     "ResourceRecords": [
                                         {"Value": "127.0.0.1"},
                                     ],
                                 },
                             ],
                             "IsTruncated": False,
                             "MaxItems": "1",
                         },
                         {
                             "HostedZoneId": TEST_HOSTED_ZONE_ID,
                             "StartRecordName": TEST_HOSTNAME + ".",
                             "StartRecordType": "A",
                             "MaxItems": "1",
                         })

    stubber.activate()
    mocker.patch("dynamisk53.app._create_route53_client").return_value = route53

    with pytest.raises(app.DynDNS2Exception, match=r"nohost"):
        app._dyndns2_handler(apigw_event, "")


def test_dyndns2_handler_no_ip_change(apigw_event, mocker):
    route53 = botocore.session.get_session().create_client("route53")
    stubber = Stubber(route53)
    stubber.add_response("list_hosted_zones",
                         {
                             "HostedZones": [{
                                 "Name": f"{TEST_DOMAIN}.",
                                 "Id": f"/hostedzone/{TEST_HOSTED_ZONE_ID}",
                                 "CallerReference": f"{TEST_CALLER_REFERENCE}",

                             }],
                             "MaxItems": "1",
                             "IsTruncated": False,
                             "Marker": "1",
                         },
                         {})
    stubber.add_response("list_resource_record_sets",
                         {
                             "ResourceRecordSets": [
                                 {
                                     "Name": f"{TEST_HOSTNAME}.",
                                     "Type": "A",
                                     "ResourceRecords": [
                                         {"Value": "1.2.3.4"},
                                     ],
                                 },
                             ],
                             "IsTruncated": False,
                             "MaxItems": "1",
                         },
                         {
                             "HostedZoneId": TEST_HOSTED_ZONE_ID,
                             "StartRecordName": TEST_HOSTNAME + ".",
                             "StartRecordType": "A",
                             "MaxItems": "1",
                         })

    stubber.activate()
    mocker.patch("dynamisk53.app._create_route53_client").return_value = route53

    assert app._dyndns2_handler(apigw_event, "") == f"nochg {TEST_MYIP}"


def test_parse_basic_auth():
    encoded = f"Basic {base64.b64encode(b'username:password').decode()}"

    u, p = app._parse_basic_auth(encoded)

    assert u == "username"
    assert p == "password"


def test_normalize_hostname():
    assert app._normalize_hostname("dynamisk53.se") == "dynamisk53.se."
    assert app._normalize_hostname("dynamisk53.se.") == "dynamisk53.se."


def test_validate_ip():
    assert app._validate_ip("127.0.0.1") == "127.0.0.1"
    with pytest.raises(app.DynDNS2Exception, match=r"badagent"):
        app._validate_ip("invalid.ip.address")
