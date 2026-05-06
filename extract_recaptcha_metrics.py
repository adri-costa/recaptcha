#!/usr/bin/env python3

import os
import csv
import json
import argparse
import subprocess
from datetime import datetime, timedelta, timezone
from google.cloud import monitoring_v3
from google.protobuf import timestamp_pb2

# Project Configuration
DEFAULT_PROJECTS = ["recaptcha-bradesco-corporivo", "recaptcha-bradesco-corprtivo2"]


def get_auth_token():
    cmd = ["gcloud", "auth", "print-access-token"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout.strip()


def get_recaptcha_keys(project_id):
    print(f"Listing reCAPTCHA keys for project: {project_id}...")
    cmd = ["gcloud", "recaptcha", "keys", "list", "--project", project_id, "--format", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"  Warning: Could not list keys for project {project_id}. Check permissions.")
        return []

    return json.loads(result.stdout)


def get_key_metrics_api(key_name, token):
    url = f"https://recaptchaenterprise.googleapis.com/v1/{key_name}/metrics"
    cmd = ["curl", "-s", "-H", f"Authorization: Bearer {token}", url]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        return {}

    return json.loads(result.stdout)


def query_time_series_by_day(client, project_id, metric_type, key_id, days_back):
    """Queries Cloud Monitoring for a metric and returns a dict mapping date string to values."""
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

    # Aggregate by day
    aggregation = monitoring_v3.Aggregation({
        "alignment_period": timedelta(days=1),
        "per_series_aligner": monitoring_v3.Aggregation.Aligner.ALIGN_SUM,
    })

    results_dict = {}  # (date, label_value) -> count

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

        for series in results:

            # Determine which label to use as "reason"
            label_val = ""

            if "label" in series.metric.labels:
                label_val = series.metric.labels["label"]

            elif "token_status" in series.metric.labels:
                label_val = series.metric.labels["token_status"]

            elif "challenge" in series.metric.labels:
                label_val = series.metric.labels["challenge"]

            for point in series.points:
                date_str = point.interval.end_time.strftime("%Y-%m-%d")
                val = int(point.value.double_value or point.value.int64_value)

                key = (date_str, label_val)
                results_dict[key] = results_dict.get(key, 0) + val

        return results_dict

    except Exception as e:
        # print(f"  Error querying {metric_type} in {project_id}: {e}")
        return {}


def main():

    parser = argparse.ArgumentParser(description="Export reCAPTCHA Metrics and Threat analysis to CSV.")

    parser.add_argument("--projects", nargs="+", default=DEFAULT_PROJECTS, help="GCP Project IDs (space separated)")
    parser.add_argument("--days", type=int, default=30, help="Number of days to look back")
    parser.add_argument("--output", default="recaptcha_detailed_threat_report.csv", help="Output CSV file name")

    args = parser.parse_args()

    token = get_auth_token()
    client = monitoring_v3.MetricServiceClient()

    # Dynamic fields for reasons found in data
    reasons_found = set()
    all_data = []  # List of rows

    print(f"Gathering data for projects: {args.projects} over {args.days} days...")

    for project_id in args.projects:

        keys = get_recaptcha_keys(project_id)

        if not keys:
            continue

        for key in keys:

            key_name = key.get("name", "")
            display_name = key.get("displayName", "")
            key_id = key_name.split("/")[-1]

            web_settings = key.get("webSettings", {})
            int_type = web_settings.get("integrationType", "MOBILE" if key.get("mobileSettings") else "N/A")

            print(f"Processing [{project_id}] {display_name} ({key_id})...")

            # 1. Get Score Buckets from reCAPTCHA API
            metrics_api = get_key_metrics_api(key_name, token)

            score_metrics = metrics_api.get("scoreMetrics", [])
            start_time_str = metrics_api.get("startTime", "")

            if start_time_str:
                base_date = datetime.fromisoformat(start_time_str.replace("Z", "+00:00"))
            else:
                base_date = datetime.now(timezone.utc) - timedelta(days=90)

            # 2. Get Reasons from Cloud Monitoring (Account Defender)
            defender_metrics = query_time_series_by_day(
                client,
                project_id,
                "recaptchaenterprise.googleapis.com/account_defender_assessment_count",
                key_id,
                args.days
            )

            # 3. Get Errors (Token Status) from Cloud Monitoring
            status_metrics = query_time_series_by_day(
                client,
                project_id,
                "recaptchaenterprise.googleapis.com/assessment_count",
                key_id,
                args.days
            )

            # Build daily rows
            for i, day_metric in enumerate(score_metrics):

                dt = base_date + timedelta(days=i)

                if dt < (datetime.now(timezone.utc) - timedelta(days=args.days)):
                    continue

                date_str = dt.strftime("%Y-%m-%d")

                overall = day_metric.get("overallMetrics", {}).get("scoreBuckets", {})

                threats = sum(int(overall.get(s, 0)) for s in ["0", "10", "20", "30", "40"])

                legitimate = sum(int(overall.get(s, 0)) for s in ["50", "60", "70", "80", "90", "100"])

                total_score_evals = sum(int(v) for v in overall.values())

                if total_score_evals == 0:
                    continue

                row = {
                    "Date": date_str,
                    "Project ID": project_id,
                    "Key Name": key_name,
                    "Display Name": display_name,
                    "Integration Type": int_type,
                    "Total Score Evals": total_score_evals,
                    "Threats (Score <= 0.4)": threats,
                    "Legitimate (Score >= 0.5)": legitimate,
                }

                # Add Account Defender Reasons
                for (d, label), val in defender_metrics.items():

                    if d == date_str:
                        col_name = f"Reason: {label}" if label else "Reason: Unspecified"

                        row[col_name] = val
                        reasons_found.add(col_name)

                # Add Status Errors
                for (d, label), val in status_metrics.items():

                    if d == date_str and label != "valid":
                        col_name = f"Error: {label}"

                        row[col_name] = val
                        reasons_found.add(col_name)

                all_data.append(row)

    if not all_data:
        print("No data found for the specified period.")
        return

    # Finalize fields
    fields = [
        "Date",
        "Project ID",
        "Key Name",
        "Display Name",
        "Integration Type",
        "Total Score Evals",
        "Threats (Score <= 0.4)",
        "Legitimate (Score >= 0.5)"
    ]

    fields += sorted(list(reasons_found))

    print(f"Writing {len(all_data)} rows to {args.output}...")

    with open(args.output, "w", newline="") as csvfile:

        writer = csv.DictWriter(csvfile, fieldnames=fields, extrasaction='ignore')

        writer.writeheader()

        for row in all_data:

            for f in fields:
                if f not in row:
                    row[f] = 0

            writer.writerow(row)

    print(f"Success! Report generated at {args.output}")


if __name__ == "__main__":
    main()