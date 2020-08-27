#!/usr/bin/env python3

import argparse
import boto3
import json
import logging
import os
import re
import requests
import subprocess
import sys
import uuid
import zlib, base64
import yaml

from datetime import datetime, date
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

SQS_BODY_LIMIT = 262144
SEVERITY = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

EXTRA_FIELDS = {
    "project": "CI_PROJECT_NAME",
    "project_url": "CI_PROJECT_URL",
    "commitsha": "CI_COMMIT_SHA",
    "commitref": "CI_COMMIT_REF_NAME",
}

FIELD_MAPPING = {
    "depcheck": {
        "severity": "severity",
        "name": "name",
        "pkg": "pkgId",
        "title": "description",
        "version": "_dummy_",
        "fixed_version": "_dummy_",
    },
    "trivy": {
        "severity": "Severity",
        "name": "VulnerabilityID",
        "pkg": "PkgName",
        "title": "Title",
        "version": "InstalledVersion",
        "fixed_version": "FixedVersion",
    },
}

SUPPORTED_MODES = ("depcheck", "trivy")


logging.basicConfig()
lg = logging.getLogger()

def parse_args():
    parser = argparse.ArgumentParser()

    group_common = parser.add_argument_group("Common")
    group_common.add_argument('-q', '--quiet', action="store_true")
    group_common.add_argument('-d', '--debug', action="store_true")
    group_common.add_argument('-m', '--mode', action="store_true", help="Supported modes: {}".format(SUPPORTED_MODES))

    group_report = parser.add_argument_group("Report settings")
    group_report.add_argument('-a', '--add', nargs='+', help="Add key=value into report")
    group_report.add_argument('-p', '--profile', nargs='+', help="Profile file path or URL. Multple URLs allowed, first one will be picked.")
    group_report.add_argument('-r', '--report', help="Report JSON file. If not set, execute scan.")

    group_es = parser.add_argument_group("Elasticsearch backend")
    group_es.add_argument('--es-server')
    group_es.add_argument('--es-username')
    group_es.add_argument('--es-password')
    group_es.add_argument('--es-enable-compression', action="store_true", help="Enable compression, might not be supported")
    group_es.add_argument('--scan-index', help="Index for overall scan results")
    group_es.add_argument('--vuln-index', help="Index for vulnerabilities")

    group_sqs = parser.add_argument_group("Amazon SQS backend")
    group_sqs.add_argument('--sqs-access-key')
    group_sqs.add_argument('--sqs-secret-key')
    group_sqs.add_argument('--sqs-region', default="us-east-2")
    group_sqs.add_argument('--sqs-url')
    group_sqs.add_argument('--scan-tag', help="Fluentd tag for overall scan results")
    group_sqs.add_argument('--vuln-tag', help="Fluentd tag for vulnerabilities")

    group_trivy = parser.add_argument_group("Trivy mode")
    group_trivy.add_argument('-i', '--image', help="Image to scan")
    group_trivy.add_argument('--fs', help="FS to scan")

    group_trivy = parser.add_argument_group("Depcheck mode")
    group_trivy.add_argument('-t', '--target', help="Target to scan", default=".")

    args = parser.parse_args()

    if not args.mode:
        if re.match(r'.*depcheck.*', parser.prog):
            args.mode = "depcheck"
        elif re.match(r'.*trivy.*', parser.prog):
            args.mode = "trivy"
        else:
            parser.error("--mode needs to be set as it cannot be determined from executable name")
    else:
        if args.mode not in SUPPORTED_MODES:
            parser.error("Mode {} is not supported. Supported modes: {}".format(args.mode, SUPPORTED_MODES))

    if not args.es_server and not args.sqs_url:
        parser.error("No backend selected, set --es-server or --sqs-url")

    if args.es_server and not (args.scan_index and args.vuln_index):
        parser.error("--scan-index and --vuln-index must be set when using Elasticsearch backend")

    if args.sqs_url and not (args.sqs_access_key and args.sqs_secret_key and args.scan_tag and args.vuln_tag):
        parser.error("--sqs-access-key, --sqs-secret-key, --scan-tag and --vuln-tag must be set when using SQS")

    if args.mode == "trivy":
        if not args.report and not args.image and not args.fs:
            parser.error("--report or --image or --fs needs to be set")

    return args

def is_trivy_report(report):
    if 'Vulnerabilities' in report:
        return True

def is_depcheck_report(report):
    if 'dependencies' in report:
        return True

def get_mode(report):
    if is_trivy_report(report):
        mode = "trivy"
    elif is_depcheck_report(report):
        mode = "depcheck"
    else:
        raise Exception("Cannot determine mode from report")
    return mode

def gen_vuln_docs(report, doc_common):
    docs = []

    if is_depcheck_report(report):
        # Depcheck
        for dep in report['dependencies']:
            for vuln in dep.get('vulnerabilities', []):
                doc = {}
                doc.update(vuln)
                doc.update({
                    'fileName': dep['fileName'],
                    'filePath': dep['filePath'],
                    'isVirtual': dep.get('isVirtual', False),
                    'packages': dep['packages'],
                    'vulnerabilityIds': dep.get('vulnerabilityIds', []),
                    # Should be name of affected package
                    'pkgId': dep['packages'][0]['id']
                })
                try:
                    doc['vulnerabilityId'] = doc['vulnerabilityIds'][0]['id']
                except Exception:
                    pass
                doc.update(doc_common)
                lg.debug("Generated doc: {}".format(doc))
                docs.append(doc)
    elif is_trivy_report(report):
        # Trivy
        if report.get('Vulnerabilities'):
            for vuln in report['Vulnerabilities']:
                vuln.update(doc_common)
                vuln['Target'] = report['Target']
                lg.debug("Generated doc: {}".format(vuln))
                docs.append(vuln)
        else:
            lg.info("No vulnerabilities in report for {}".format(report.get('Target')))
    else:
        raise Exception("Unknown report structure")

    return docs

def sqs_prepare_body(body):
    return base64.b64encode(zlib.compress(json.dumps(body).encode('utf-8'))).decode('ascii')

def get_field(mode, field):
    return FIELD_MAPPING[mode][field]

def gen_summary(report, severity=None, ignore_unfixed=False, whitelist=None, vulnerabilities=None):
    summary = {}
    fail = False

    mode = get_mode(report)

    for vuln in vulnerabilities:
        vuln_severity = vuln[get_field(mode, 'severity')]
        vuln_name = vuln[get_field(mode, 'name')]
        vuln_pkg = vuln[get_field(mode, 'pkg')]
        try:
            summary[vuln_severity].append(vuln)
        except KeyError:
            summary[vuln_severity] = [vuln]

        # Fail if severity above threshold
        if severity and SEVERITY[vuln_severity] >= SEVERITY[severity]:
            lg.debug("Not failing for vulnerability {} as it's severity is lower than {}".format(vuln_name, severity))
            skipped = False
            if whitelist:
                for wl in whitelist['vulnerabilities']:
                    if wl['name'] == vuln_name:
                        # We matched vulnerability in our whitelist
                        if wl.get('until') and wl['until'] < date.today():
                            # Check if it didn't expired
                            lg.warning("Whitelist of {} expired at {}".format(wl['name'], wl['until']))
                            continue

                        if wl.get('severity'):
                            # Check if severity matches
                            if SEVERITY[wl['severity']] >= SEVERITY[vuln_severity]:
                                lg.info("Ignoring whitelisted vulnerability {}".format(wl['name']))
                                skipped = True
                            else:
                                lg.warning("Whitelist of {} doesn't match actual severity ({} > {})".format(wl['name'], vuln_severity, wl['severity']))

                    if wl.get('package'):
                        # Check if package matches
                        if wl['package'] == vuln_pkg:
                            if wl.get('severity'):
                                # Check if severity matches
                                if SEVERITY[wl['severity']] >= SEVERITY[vuln_severity]:
                                    lg.info("Ignoring vulnerability {} of whitelisted package {}".format(wl['name'], wl['package']))
                                    skipped = True
                                else:
                                    lg.warning("Whitelist of package {} for vulnerability {} doesn't match actual severity ({} > {})".format(wl['package'], wl['name'], vuln_severity, wl['severity']))
                            else:
                                lg.info("Ignoring vulnerability {} of whitelisted package {}".format(wl['name'], wl['package']))
                                skipped = True

            if ignore_unfixed == True and not vuln.get(get_field(mode, "fixed_version")):
                lg.warning("Not failing for {} ({}) as it doesn't have fixed version".format(vuln_name, vuln_pkg))
                skipped = True

            if not skipped:
                fail = True
                lg.info("{}\t{}\t{}-{} (fix: {})\t{}".format(
                    vuln_severity,
                    vuln_name,
                    vuln_pkg,
                    vuln.get(get_field(mode, 'version')),
                    vuln.get(get_field(mode, 'fixed_version'), 'n/a'),
                    vuln[get_field(mode, 'title')]
                ))

    ret = {'summary':{}}
    total = 0
    for level in summary.keys():
        ret['summary'][level] = len(summary[level])
        total += len(summary[level])
    ret['summary']['total'] = total
    ret['summary']['fail'] = fail
    return ret

def main():
    args = parse_args()

    if args.quiet:
        lg.setLevel(logging.ERROR)
    else:
        lg.setLevel(logging.INFO)

    if args.debug:
        lg.setLevel(logging.DEBUG)

    es = None
    if args.es_server:
        es_conn_kwargs = {
            'http_compress': args.es_enable_compression,
        }
        if args.es_username:
            es_conn_kwargs['http_auth'] = (args.es_username, args.es_password)

        lg.debug("Connecting to Elasticsearch {}".format(args.es_server))
        es = Elasticsearch([args.es_server], **es_conn_kwargs)

    sqs = None
    if args.sqs_url:
        lg.debug("Connecting to SQS {}".format(args.sqs_url))
        sqs = boto3.client('sqs',
            region_name=args.sqs_region,
            aws_access_key_id=args.sqs_access_key,
            aws_secret_access_key=args.sqs_secret_key)

    doc_common = {
        "@timestamp": datetime.utcnow().isoformat("T")+"Z",
        'report_id':  str(uuid.uuid1()),
    }
    if args.add:
        for add in args.add:
            add = add.split('=')
            doc_common[add[0]] = add[1]

    for key, env in EXTRA_FIELDS.items():
        if not doc_common.get(key) and os.getenv(env):
            doc_common[key] = os.getenv(env)
    if not doc_common.get("image") and os.getenv("RELEASE_IMAGE_NAME"):
        doc_common["image"] = "{}:{}".format(os.getenv("RELEASE_IMAGE_NAME"), os.getenv("CI_COMMIT_SHA"))

    lg.debug("Generated common doc fields: {}".format(doc_common))

    if args.profile:
        # Fetch profile
        fetched = False
        for profile_url in args.profile:
            lg.info("Fetching profile {}".format(os.path.basename(profile_url.split('?')[0])))
            try:
                req = requests.get(profile_url)
                if req.status_code != 200:
                    raise Exception("Server returned unexpected status code {}: {}".format(req.status_code, req.text))
                profile = yaml.load(req.text, Loader=yaml.FullLoader).get('profile', {})
                fetched = True
                break
            except Exception as e:
                lg.error(e)

        if not fetched:
            lg.error("Failed to fetch profile, see errors above.")
            sys.exit(1)

    report_file = args.report
    if not report_file:
        # Run scan on our own
        if args.mode == "trivy":
            if args.image:
                lg.info("Executing trivy scan on image {}".format(args.image))
                p = subprocess.call(["trivy", "image", "-f", "json", "-o", "trivy-report.json", "--no-progress", "--vuln-type", "os", "--input", args.image])
            if args.fs:
                lg.info("Executing trivy scan on fs {}".format(args.fs))
                p = subprocess.call(["trivy", "fs", "-f", "json", "-o", "trivy-report.json", "--no-progress", "--vuln-type", "library", args.fs])
            report_file = "trivy-report.json"
        elif args.mode == "depcheck":
            lg.info("Executing depcheck scan on target {}".format(args.target))
            p = subprocess.call(["dependency-check", "--enableExperimental", "--scan", args.target, "--project", doc_common.get('project', 'unknown'), "-f", "ALL"])
            report_file = "dependency-check-report.json"

    lg.debug("Loading report file {}".format(report_file))
    with open(report_file, 'r') as fh:
        reports = json.load(fh)
        if args.mode == "depcheck":
            # Depcheck has only single report in a file
            reports = [reports]

    if not reports:
        lg.warning("No reports available")
        sys.exit(0)

    fail = False
    for report in reports:
        # Try to find execution timestamp if present
        if args.mode == "depcheck":
            try:
                doc_common['@timestamp'] = report['projectInfo']['reportDate']
            except (KeyError, ValueError):
                lg.error("No reportDate in report, using current timestamp")

        vulnerabilities = gen_vuln_docs(report, doc_common)

        # Alter report with common fields
        report.update(doc_common)
        report.update(gen_summary(report,
            profile.get(args.mode, {}).get('severity', None),
            profile.get(args.mode, {}).get('ignore_unfixed', False),
            profile.get('whitelist'), vulnerabilities))
        lg.debug("Generated doc: {}".format(report))

        if es:
            lg.info("Sending report id {} with {} vulnerabilities into elasticsearch ({})".format(report['report_id'], len(vulnerabilities), report.get('Target')))
            es.index(index=args.scan_index, body=report)
            bulk(es, vulnerabilities, index=args.vuln_index)

        if sqs:
            lg.info("Sending report id {} with {} vulnerabilities into SQS ({})".format(report['report_id'], len(vulnerabilities), report.get('Target')))
            report['tag'] = args.scan_tag


            for vuln in vulnerabilities:
                sqs_kwargs = {}
                if re.match(r'.*\.fifo$', args.sqs_url):
                    sqs_kwargs["MessageDeduplicationId"] = str(uuid.uuid1())
                    sqs_kwargs["MessageGroupId"] = doc_common['report_id']

                vuln['tag'] = args.vuln_tag
                sqs.send_message(
                    QueueUrl=args.sqs_url,
                    MessageBody=sqs_prepare_body(vuln),
                    **sqs_kwargs,
                )

            msgbody = sqs_prepare_body(report)
            if len(msgbody.encode('utf-8')) >= SQS_BODY_LIMIT:
                lg.warning("Scan report size is bigger than SQS allowed 262144 bytes. Removing some fields.")
                if args.mode == "trivy":
                    report['Vulnerabilities'] = []
                if args.mode == "depcheck":
                    report['dependencies'] = []
                msgbody = sqs_prepare_body(report)

            sqs_kwargs = {}
            if re.match(r'.*\.fifo$', args.sqs_url):
                sqs_kwargs["MessageDeduplicationId"] = str(uuid.uuid1())
                sqs_kwargs["MessageGroupId"] = doc_common['report_id']

            sqs.send_message(
                QueueUrl=args.sqs_url,
                MessageBody=msgbody,
                **sqs_kwargs,
            )

        if report['summary']['fail']:
            fail = True
        lg.info("Summary: {}".format(report['summary']))

    if fail:
        lg.error("Vulnerabilities of {} severity and above found, failing.".format(profile[args.mode]['severity']))
        sys.exit(1)

if __name__ == '__main__':
    main()
