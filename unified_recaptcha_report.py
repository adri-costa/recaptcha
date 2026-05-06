#!/usr/bin/env python3

import argparse
import pandas as pd
from datetime import datetime, timedelta, timezone
from google.cloud import recaptchaenterprise_v1
from google.cloud import monitoring_v3
from google.protobuf.json_format import MessageToDict
from google.protobuf import timestamp_pb2

# Default Project Configuration
DEFAULT_PROJECTS = ["recaptcha-bradesco-corportivo", "recaptcha-bradesco-corprtivo2"]


def query_monitoring_metrics(client, project_id, metric_type, key_id, days_back):
    """Queries Cloud Monitoring for time-series metrics (Reasons/Errors) and returns a dict mapping (date, label) -> count."""

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

    results_dict = {}

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

            label_val = ""

            if "reason" in series.metric.labels:
                label_val = series.metric.labels["reason"]

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

    except Exception:
        return {}


def main():

    parser = argparse.ArgumentParser(description="Unified reCAPTCHA Comprehensive Report (SDK + Monitoring)")

    parser.add_argument("--projects", nargs="+", default=DEFAULT_PROJECTS, help="GCP Project IDs")
    parser.add_argument("--days", type=int, default=30, help="Days to look back")
    parser.add_argument("--output", default="relatorio_consolidado_v2.csv", help="Output file")

    args = parser.parse_args()

    recaptcha_client = recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient()
    monitoring_client = monitoring_v3.MetricServiceClient()

    all_rows = []
    extra_columns = set()  # To track dynamic Reason/Error columns

    print(f"Iniciando extração consolidada para: {args.projects}")

    for project_id in args.projects:

        print(f"Processando projeto: {project_id}...")

        parent = f"projects/{project_id}"

        try:
            keys = recaptcha_client.list_keys(parent=parent)

        except Exception as e:
            print(f"Erro ao listar chaves no projeto {project_id}: {e}")
            continue

        for key in keys:

            key_name = key.name
            display_name = key.display_name
            site_key = key_name.split("/")[-1]

            print(f"  Extraindo métricas da chave: {display_name} ({site_key})")

            # 1. SDK: Get Granular Score Metrics
            metrics_request = recaptchaenterprise_v1.GetMetricsRequest(name=f"{key_name}/metrics")

            try:
                metrics_pb = recaptcha_client.get_metrics(request=metrics_request)

                metrics_dict = MessageToDict(metrics_pb)

            except Exception as e:
                print(f"    Erro ao buscar GetMetrics: {e}")

                metrics_dict = {}

            # 2. Monitoring: Get Account Defender Reasons
            defender_metrics = query_monitoring_metrics(
                monitoring_client,
                project_id,
                "recaptchaenterprise.googleapis.com/account_defender_assessment_count",
                site_key,
                args.days
            )

            # 3. Monitoring: Get Token Status/Errors
            status_metrics = query_monitoring_metrics(
                monitoring_client,
                project_id,
                "recaptchaenterprise.googleapis.com/assessment_count",
                site_key,
                args.days
            )

            # Process Score Metrics from SDK
            if 'scoreMetrics' in metrics_dict:

                start_time_str = metrics_dict.get('startTime')

                if start_time_str:

                    # Parse start_time to datetime object
                    base_date = datetime.fromisoformat(start_time_str.replace("Z", "+00:00"))

                else:
                    base_date = datetime.now(timezone.utc) - timedelta(days=90)

                for i, day_data in enumerate(metrics_dict['scoreMetrics']):

                    # Calculate date for this entry
                    dt_obj = base_date + timedelta(days=i)

                    date_str = dt_obj.strftime("%Y-%m-%d")

                    # Filter by days_back
                    if dt_obj < (datetime.now(timezone.utc) - timedelta(days=args.days)):
                        continue

                    buckets = day_data.get('overallMetrics', {}).get('scoreBuckets', {})

                    row = {
                        'data': date_str,
                        'projeto': project_id,
                        'nome_chave': display_name,
                        'site_key': site_key,

                        # Scores granulares (map 0-100 to 0.0-1.0)
                        'score_0.0': buckets.get('0', 0),
                        'score_0.1': buckets.get('10', 0),
                        'score_0.2': buckets.get('20', 0),
                        'score_0.3': buckets.get('30', 0),
                        'score_0.4': buckets.get('40', 0),
                        'score_0.5': buckets.get('50', 0),
                        'score_0.6': buckets.get('60', 0),
                        'score_0.7': buckets.get('70', 0),
                        'score_0.8': buckets.get('80', 0),
                        'score_0.9': buckets.get('90', 0),
                        'score_1.0': buckets.get('100', 0),
                    }

                    # Add Account Defender Reasons (from Monitoring)
                    for (d, label), val in defender_metrics.items():

                        if d == date_str:

                            col_name = f"Motivo: {label}" if label else "Motivo: Indefinido"

                            row[col_name] = val

                            extra_columns.add(col_name)

                    # Add Token Status/Errors (from Monitoring)
                    for (d, label), val in status_metrics.items():

                        if d == date_str and label != "valid":

                            col_name = f"Erro: {label}"

                            row[col_name] = val

                            extra_columns.add(col_name)

                    all_rows.append(row)

    if not all_rows:
        print("Nenhum dado encontrado para o período e projetos selecionados.")
        return

    # Finalize DataFrame
    df = pd.DataFrame(all_rows)

    # Organize columns: Metadata -> Scores -> Reasons -> Errors
    base_cols = ['data', 'projeto', 'nome_chave', 'site_key']

    score_cols = [f'score_{i/10:.1f}' for i in range(0, 11)]

    reason_cols = sorted([c for c in extra_columns if c.startswith("Motivo:")])

    error_cols = sorted([c for c in extra_columns if c.startswith("Erro:")])

    final_columns = base_cols + score_cols + reason_cols + error_cols

    df = df.reindex(columns=final_columns).fillna(0)

    # Save
    df.to_csv(args.output, index=False)

    print(f"\nSucesso! Relatório consolidado gerado em: {args.output}")

    print(f"Total de linhas: {len(df)}")


if __name__ == "__main__":
    main()