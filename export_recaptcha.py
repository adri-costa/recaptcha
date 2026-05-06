#!/usr/bin/env python3

import os
import csv
import json
import argparse
import subprocess
from datetime import datetime, timedelta, timezone
from google.cloud import monitoring_v3
from google.protobuf import timestamp_pb2


def get_recaptcha_keys(project_id):
    """List all reCAPTCHA Enterprise keys in the project."""
    print(f"Listing reCAPTCHA keys for project: {project_id}...")
    cmd = ["gcloud", "recaptcha", "keys", "list", "--project", project_id, "--format", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error listing keys in {project_id}: {result.stderr}")
        return []

    return json.loads(result.stdout)


def query_metric_sum(client, project_id, metric_type, key_id, days_back, extra_filter=""):
    """Query the sum of a specific metric over the last N days."""
    project_name = f"projects/{project_id}"
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(days=days_back)

    interval = monitoring_v3.TimeInterval()
    end_ts = timestamp_pb2.Timestamp()
    end_ts.FromDatetime(now)
    interval.end_time = end_ts

    start_ts = timestamp_pb2.Timestamp()
    start_ts.FromDatetime(start_time)
    interval.start_time = start_ts

    filter_str = f'metric.type = "{metric_type}" AND resource.labels.key_id = "{key_id}"'

    if extra_filter:
        filter_str += f" AND ({extra_filter})"

    aggregation = monitoring_v3.Aggregation({
        "alignment_period": timedelta(days=days_back),
        "per_series_aligner": monitoring_v3.Aggregation.Aligner.ALIGN_SUM,
        "cross_series_reducer": monitoring_v3.Aggregation.Reducer.REDUCE_SUM,
    })

    try:
        results = client.list_time_series(
            request={
                "name": project_name,
                "filter": filter_str,
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
                "aggregation": aggregation
            }
        )

        total = 0

        for series in results:
            for point in series.points:
                if point.value.distribution_value.count:
                    total += point.value.distribution_value.count
                else:
                    total += point.value.double_value or point.value.int64_value

        return int(total)

    except Exception:
        return 0


def main():
    parser = argparse.ArgumentParser(description="Export reCAPTCHA Enterprise report to CSV for one or more projects.")

    parser.add_argument(
        "--projects",
        nargs="+",
        required=True,
        help="GCP Project IDs (space-separated). Example: --projects proj1 proj2"
    )

    parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="Number of days to look back (default: 30)"
    )

    parser.add_argument(
        "--output",
        default="recaptcha_report.csv",
        help="Output CSV file name"
    )

    args = parser.parse_args()

    client = monitoring_v3.MetricServiceClient()

    fields = [
        "Project ID",
        "Name",
        "Site Key Type",
        "WAF Type",
        "Created",
        "Project#",
        "Top Domain",
        "ID",
        "Key",
        "Consumer Assessments",
        "Enterprise Assessments",
        "Executes",
        "GCP Assessments",
        "Non Gcp Assessments",
        "Mobile Sdk Assessments",
        "V2 Web Assessments",
        "V2 Pbc Assessments",
        "Challenged Sessions",
        "Challenged Sessions No Assessments",
        "V3 Web Assessments",
        "Payment Fraud Assessments",
        "Smsd Assessments",
        "Errors"
    ]

    print(f"Starting report generation for projects: {', '.join(args.projects)}")

    with open(args.output, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields)
        writer.writeheader()

        for project_id in args.projects:
            keys = get_recaptcha_keys(project_id)

            if not keys:
                print(f"No keys found or access error for project: {project_id}")
                continue

            print(f"Processing {len(keys)} keys in project {project_id} over {args.days} days...")

            for key in keys:
                display_name = key.get("displayName", "")
                key_full_name = key.get("name", "")
                key_id = key_full_name.split("/")[-1]
                project_num = key_full_name.split("/")[1]
                created = key.get("createTime", "")

                web_settings = key.get("webSettings", {})
                mobile_settings = key.get("mobileSettings", {})

                if web_settings:
                    int_type = web_settings.get("integrationType", "N/A")
                    top_domain = web_settings.get("allowedDomains", [""])[0]

                elif mobile_settings:
                    int_type = "MOBILE"
                    top_domain = "N/A"

                else:
                    int_type = "N/A"
                    top_domain = ""

                waf_type = key.get("wafSettings", {}).get("wafFeature", "NONE")

                print(f"  [{project_id}] Processing {display_name} ({key_id})...")

                m_assess_labels = "recaptchaenterprise.googleapis.com/assessments"
                m_assess_count = "recaptchaenterprise.googleapis.com/assessment_count"
                m_exec = "recaptchaenterprise.googleapis.com/executes"

                total_assess = query_metric_sum(
                    client,
                    project_id,
                    m_assess_count,
                    key_id,
                    args.days
                )

                row = {
                    "Project ID": project_id,
                    "Name": display_name,
                    "Site Key Type": int_type,
                    "WAF Type": waf_type,
                    "Created": created,
                    "Project#": project_num,
                    "Top Domain": top_domain,
                    "ID": key_id,
                    "Key": key_id,
                    "Consumer Assessments": 0,
                    "Enterprise Assessments": total_assess,

                    "Executes": query_metric_sum(
                        client,
                        project_id,
                        m_exec,
                        key_id,
                        args.days
                    ),

                    "GCP Assessments": query_metric_sum(
                        client,
                        project_id,
                        m_assess_labels,
                        key_id,
                        args.days,
                        'metric.labels.platform = "web"'
                    ),

                    "Non Gcp Assessments": query_metric_sum(
                        client,
                        project_id,
                        m_assess_labels,
                        key_id,
                        args.days,
                        'metric.labels.platform != "web"'
                    ),

                    "Mobile Sdk Assessments": query_metric_sum(
                        client,
                        project_id,
                        m_assess_labels,
                        key_id,
                        args.days,
                        'metric.labels.platform = "android" OR metric.labels.platform = "ios"'
                    ),

                    "V2 Web Assessments": total_assess if int_type in ["CHECKBOX", "INVISIBLE"] else 0,

                    "V2 Pbc Assessments": 0,

                    "Challenged Sessions": query_metric_sum(
                        client,
                        project_id,
                        m_assess_labels,
                        key_id,
                        args.days,
                        'metric.labels.challenge = "challenge"'
                    ),

                    "Challenged Sessions No Assessments": 0,

                    "V3 Web Assessments": total_assess if int_type == "SCORE" else 0,

                    "Payment Fraud Assessments": 0,

                    "Smsd Assessments": query_metric_sum(
                        client,
                        project_id,
                        "recaptchaenterprise.googleapis.com/sms_toll_fraud_risks",
                        key_id,
                        args.days
                    ),

                    "Errors": query_metric_sum(
                        client,
                        project_id,
                        m_assess_count,
                        key_id,
                        args.days,
                        'metric.labels.token_status != "valid"'
                    )
                }

                writer.writerow(row)

    print(f"\nCombined report successfully generated at {args.output}")


if __name__ == "__main__":
    main()