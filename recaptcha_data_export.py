#!/usr/bin/env python3

import csv
import argparse
import logging
from datetime import datetime, timedelta, timezone

from google.cloud import recaptchaenterprise_v1
from google.cloud import monitoring_v3
from google.protobuf.json_format import MessageToDict
from google.protobuf import timestamp_pb2
from google.api_core.exceptions import GoogleAPICallError, PermissionDenied, NotFound


DEFAULT_PROJECTS = [
    "recaptcha-bradesco-corportivo",
    "recaptcha-bradesco-corprtivo2"
]


SCORE_COLUMNS = [
    "score_0.0",
    "score_0.1",
    "score_0.2",
    "score_0.3",
    "score_0.4",
    "score_0.5",
    "score_0.6",
    "score_0.7",
    "score_0.8",
    "score_0.9",
    "score_1.0",
]


def setup_logging(debug):
    level = logging.DEBUG if debug else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(message)s"
    )


def safe_divide(numerator, denominator):
    try:
        numerator = float(numerator or 0)
        denominator = float(denominator or 0)

        if denominator == 0:
            return 0

        return round(numerator / denominator, 6)

    except Exception:
        return 0


def proto_datetime_to_string(value):
    if not value:
        return ""

    try:
        return value.isoformat()
    except Exception:
        return str(value)


def enum_to_string(value):
    try:
        return value.name
    except Exception:
        return str(value)


def sanitize_dynamic_label(label):
    if not label:
        return "indefinido"

    normalized = str(label).strip().lower()
    normalized = normalized.replace(" ", "_")
    normalized = normalized.replace("/", "_")
    normalized = normalized.replace("-", "_")
    normalized = normalized.replace(".", "_")
    normalized = normalized.replace("\n", "_")
    normalized = normalized.replace("\t", "_")
    normalized = normalized.replace("__", "_")

    safe_chars = []
    for ch in normalized:
        if ch.isalnum() or ch == "_":
            safe_chars.append(ch)
        else:
            safe_chars.append("_")

    normalized = "".join(safe_chars).strip("_")
    return normalized or "indefinido"


def get_key_metadata(key, project_id):
    key_name = key.name
    site_key = key_name.split("/")[-1]

    display_name = getattr(key, "display_name", "")
    create_time = proto_datetime_to_string(getattr(key, "create_time", ""))

    integration_type = "N/A"
    top_domain = ""
    waf_type = "NONE"

    try:
        if key.web_settings:
            integration_type = enum_to_string(key.web_settings.integration_type)

            if key.web_settings.allowed_domains:
                top_domain = key.web_settings.allowed_domains[0]

        elif key.android_settings or key.ios_settings:
            integration_type = "MOBILE"
            top_domain = "N/A"

    except Exception as e:
        logging.warning("Falha ao extrair web/mobile settings da chave %s: %s", key_name, e)

    try:
        if key.waf_settings:
            waf_type = enum_to_string(key.waf_settings.waf_feature)
    except Exception as e:
        logging.warning("Falha ao extrair waf_settings da chave %s: %s", key_name, e)

    return {
        "project_id": project_id,
        "key_name": key_name,
        "display_name": display_name,
        "site_key": site_key,
        "integration_type": integration_type,
        "top_domain": top_domain,
        "waf_type": waf_type,
        "created": create_time,
    }


def build_interval(days_back):
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(days=days_back)

    interval = monitoring_v3.TimeInterval()

    end_ts = timestamp_pb2.Timestamp()
    end_ts.FromDatetime(now)
    interval.end_time = end_ts

    start_ts = timestamp_pb2.Timestamp()
    start_ts.FromDatetime(start_time)
    interval.start_time = start_ts

    return interval


def read_point_value(point):
    try:
        if point.value.distribution_value.count:
            return int(point.value.distribution_value.count)
    except Exception:
        pass

    try:
        return int(point.value.double_value or point.value.int64_value or 0)
    except Exception:
        return 0


def query_metric_sum(client, project_id, metric_type, key_id, days_back, extra_filter=""):
    project_name = f"projects/{project_id}"
    interval = build_interval(days_back)

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
                "aggregation": aggregation,
            }
        )

        total = 0

        for series in results:
            for point in series.points:
                total += read_point_value(point)

        return int(total)

    except PermissionDenied as e:
        logging.error("Permissão negada ao consultar métrica %s no projeto %s / key %s: %s", metric_type, project_id, key_id, e)
        return 0

    except NotFound as e:
        logging.error("Métrica/projeto não encontrado: %s | projeto=%s | key=%s | erro=%s", metric_type, project_id, key_id, e)
        return 0

    except GoogleAPICallError as e:
        logging.error("Erro Google API ao consultar métrica %s no projeto %s / key %s: %s", metric_type, project_id, key_id, e)
        return 0

    except Exception as e:
        logging.exception("Erro inesperado ao consultar métrica %s no projeto %s / key %s: %s", metric_type, project_id, key_id, e)
        return 0


def query_monitoring_daily_labels(client, project_id, metric_type, key_id, days_back):
    project_name = f"projects/{project_id}"
    interval = build_interval(days_back)

    filter_str = f'metric.type = "{metric_type}" AND resource.labels.key_id = "{key_id}"'

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
                "aggregation": aggregation,
            }
        )

        for series in results:
            label_val = ""

            if "reason" in series.metric.labels:
                label_val = series.metric.labels["reason"]

            elif "label" in series.metric.labels:
                label_val = series.metric.labels["label"]

            elif "token_status" in series.metric.labels:
                label_val = series.metric.labels["token_status"]

            elif "challenge" in series.metric.labels:
                label_val = series.metric.labels["challenge"]

            for point in series.points:
                date_str = point.interval.end_time.strftime("%Y-%m-%d")
                val = read_point_value(point)

                key = (date_str, label_val)
                results_dict[key] = results_dict.get(key, 0) + val

        return results_dict

    except PermissionDenied as e:
        logging.error("Permissão negada ao consultar labels da métrica %s no projeto %s / key %s: %s", metric_type, project_id, key_id, e)
        return {}

    except NotFound as e:
        logging.error("Métrica/projeto não encontrado: %s | projeto=%s | key=%s | erro=%s", metric_type, project_id, key_id, e)
        return {}

    except GoogleAPICallError as e:
        logging.error("Erro Google API ao consultar labels da métrica %s no projeto %s / key %s: %s", metric_type, project_id, key_id, e)
        return {}

    except Exception as e:
        logging.exception("Erro inesperado ao consultar labels da métrica %s no projeto %s / key %s: %s", metric_type, project_id, key_id, e)
        return {}


def get_sdk_metrics(recaptcha_client, key_name):
    try:
        request = recaptchaenterprise_v1.GetMetricsRequest(
            name=f"{key_name}/metrics"
        )

        metrics_pb = recaptcha_client.get_metrics(request=request)
        return MessageToDict(metrics_pb)

    except PermissionDenied as e:
        logging.error("Permissão negada ao executar GetMetrics para %s: %s", key_name, e)
        return {}

    except NotFound as e:
        logging.error("Métrica não encontrada via GetMetrics para %s: %s", key_name, e)
        return {}

    except GoogleAPICallError as e:
        logging.error("Erro Google API no GetMetrics para %s: %s", key_name, e)
        return {}

    except Exception as e:
        logging.exception("Erro inesperado no GetMetrics para %s: %s", key_name, e)
        return {}


def calculate_summary_metrics(monitoring_client, project_id, site_key, integration_type, days):
    m_assess_labels = "recaptchaenterprise.googleapis.com/assessments"
    m_assess_count = "recaptchaenterprise.googleapis.com/assessment_count"
    m_exec = "recaptchaenterprise.googleapis.com/executes"
    m_sms = "recaptchaenterprise.googleapis.com/sms_toll_fraud_risks"

    total_assess = query_metric_sum(
        monitoring_client,
        project_id,
        m_assess_count,
        site_key,
        days
    )

    executes = query_metric_sum(
        monitoring_client,
        project_id,
        m_exec,
        site_key,
        days
    )

    challenged_sessions = query_metric_sum(
        monitoring_client,
        project_id,
        m_assess_labels,
        site_key,
        days,
        'metric.labels.challenge = "challenge"'
    )

    errors = query_metric_sum(
        monitoring_client,
        project_id,
        m_assess_count,
        site_key,
        days,
        'metric.labels.token_status != "valid"'
    )

    summary = {
        "consumer_assessments": 0,
        "enterprise_assessments": total_assess,
        "executes": executes,

        "gcp_assessments": query_metric_sum(
            monitoring_client,
            project_id,
            m_assess_labels,
            site_key,
            days,
            'metric.labels.platform = "web"'
        ),

        "non_gcp_assessments": query_metric_sum(
            monitoring_client,
            project_id,
            m_assess_labels,
            site_key,
            days,
            'metric.labels.platform != "web"'
        ),

        "mobile_sdk_assessments": query_metric_sum(
            monitoring_client,
            project_id,
            m_assess_labels,
            site_key,
            days,
            'metric.labels.platform = "android" OR metric.labels.platform = "ios"'
        ),

        "v2_web_assessments_estimated": total_assess if integration_type in ["CHECKBOX", "INVISIBLE"] else 0,
        "v3_web_assessments_estimated": total_assess if integration_type == "SCORE" else 0,

        "v2_pbc_assessments": 0,
        "challenged_sessions": challenged_sessions,
        "challenged_sessions_no_assessments": 0,
        "payment_fraud_assessments": 0,

        "smsd_assessments": query_metric_sum(
            monitoring_client,
            project_id,
            m_sms,
            site_key,
            days
        ),

        "errors": errors,
    }

    summary["error_rate"] = safe_divide(errors, total_assess)
    summary["challenge_rate"] = safe_divide(challenged_sessions, total_assess)
    summary["execute_to_assessment_rate"] = safe_divide(executes, total_assess)

    return summary


def build_score_row(metadata, summary_metrics, date_str, buckets):
    row = {}

    row.update(metadata)
    row.update(summary_metrics)

    row["date"] = date_str
    row["record_type"] = "daily_score_metric"

    row["score_0.0"] = buckets.get("0", 0)
    row["score_0.1"] = buckets.get("10", 0)
    row["score_0.2"] = buckets.get("20", 0)
    row["score_0.3"] = buckets.get("30", 0)
    row["score_0.4"] = buckets.get("40", 0)
    row["score_0.5"] = buckets.get("50", 0)
    row["score_0.6"] = buckets.get("60", 0)
    row["score_0.7"] = buckets.get("70", 0)
    row["score_0.8"] = buckets.get("80", 0)
    row["score_0.9"] = buckets.get("90", 0)
    row["score_1.0"] = buckets.get("100", 0)

    threats = sum(
        int(buckets.get(s, 0)) for s in ["0", "10", "20", "30", "40"]
    )

    legitimate = sum(
        int(buckets.get(s, 0)) for s in ["50", "60", "70", "80", "90", "100"]
    )

    total_score_evals = sum(
        int(v) for v in buckets.values()
    )

    row["threats_score_0_0_to_0_4"] = threats
    row["legitimate_score_0_5_to_1_0"] = legitimate
    row["total_score_evals"] = total_score_evals

    row["threat_rate"] = safe_divide(threats, total_score_evals)
    row["legitimate_rate"] = safe_divide(legitimate, total_score_evals)
    row["score_low_ratio"] = safe_divide(threats, total_score_evals)
    row["score_high_ratio"] = safe_divide(legitimate, total_score_evals)

    return row


def build_summary_only_row(metadata, summary_metrics, extraction_timestamp, days):
    row = {}

    row.update(metadata)
    row.update(summary_metrics)

    row["date"] = ""
    row["record_type"] = "summary_only"
    row["extraction_timestamp"] = extraction_timestamp
    row["report_days"] = days

    for score_col in SCORE_COLUMNS:
        row[score_col] = 0

    row["total_score_evals"] = 0
    row["threats_score_0_0_to_0_4"] = 0
    row["legitimate_score_0_5_to_1_0"] = 0
    row["threat_rate"] = 0
    row["legitimate_rate"] = 0
    row["score_low_ratio"] = 0
    row["score_high_ratio"] = 0

    return row


def main():
    parser = argparse.ArgumentParser(
        description="Unified quick-win Google reCAPTCHA Enterprise CSV report"
    )

    parser.add_argument(
        "--projects",
        nargs="+",
        default=DEFAULT_PROJECTS,
        help="GCP Project IDs"
    )

    parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="Days to look back"
    )

    parser.add_argument(
        "--output",
        default="recaptcha_unified_quickwin.csv",
        help="Output CSV file"
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )

    args = parser.parse_args()

    setup_logging(args.debug)

    recaptcha_client = recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient()
    monitoring_client = monitoring_v3.MetricServiceClient()

    all_rows = []
    dynamic_columns = set()

    extraction_timestamp = datetime.now(timezone.utc).isoformat()

    logging.info("Iniciando extração unificada")
    logging.info("Projetos: %s", args.projects)
    logging.info("Período: últimos %s dias", args.days)
    logging.info("Arquivo de saída: %s", args.output)

    for project_id in args.projects:
        logging.info("Processando projeto: %s", project_id)

        parent = f"projects/{project_id}"

        try:
            keys = recaptcha_client.list_keys(parent=parent)

        except PermissionDenied as e:
            logging.error("Permissão negada ao listar chaves no projeto %s: %s", project_id, e)
            continue

        except NotFound as e:
            logging.error("Projeto não encontrado ao listar chaves %s: %s", project_id, e)
            continue

        except GoogleAPICallError as e:
            logging.error("Erro Google API ao listar chaves no projeto %s: %s", project_id, e)
            continue

        except Exception as e:
            logging.exception("Erro inesperado ao listar chaves no projeto %s: %s", project_id, e)
            continue

        for key in keys:
            metadata = get_key_metadata(key, project_id)

            logging.info(
                "Extraindo chave: %s (%s)",
                metadata["display_name"],
                metadata["site_key"]
            )

            summary_metrics = calculate_summary_metrics(
                monitoring_client,
                metadata["project_id"],
                metadata["site_key"],
                metadata["integration_type"],
                args.days
            )

            sdk_metrics = get_sdk_metrics(
                recaptcha_client,
                metadata["key_name"]
            )

            defender_metrics = query_monitoring_daily_labels(
                monitoring_client,
                metadata["project_id"],
                "recaptchaenterprise.googleapis.com/account_defender_assessment_count",
                metadata["site_key"],
                args.days
            )

            status_metrics = query_monitoring_daily_labels(
                monitoring_client,
                metadata["project_id"],
                "recaptchaenterprise.googleapis.com/assessment_count",
                metadata["site_key"],
                args.days
            )

            score_metrics = sdk_metrics.get("scoreMetrics", [])
            start_time_str = sdk_metrics.get("startTime", "")

            if start_time_str:
                try:
                    base_date = datetime.fromisoformat(
                        start_time_str.replace("Z", "+00:00")
                    )
                except ValueError:
                    logging.warning(
                        "startTime inválido para chave %s: %s",
                        metadata["site_key"],
                        start_time_str
                    )
                    base_date = datetime.now(timezone.utc) - timedelta(days=90)
            else:
                base_date = datetime.now(timezone.utc) - timedelta(days=90)

            rows_added_for_key = 0

            for i, day_data in enumerate(score_metrics):
                dt_obj = base_date + timedelta(days=i)

                if dt_obj < (datetime.now(timezone.utc) - timedelta(days=args.days)):
                    continue

                date_str = dt_obj.strftime("%Y-%m-%d")
                buckets = day_data.get("overallMetrics", {}).get("scoreBuckets", {})

                row = build_score_row(
                    metadata,
                    summary_metrics,
                    date_str,
                    buckets
                )

                row["extraction_timestamp"] = extraction_timestamp
                row["report_days"] = args.days

                for (d, label), val in defender_metrics.items():
                    if d == date_str:
                        sanitized = sanitize_dynamic_label(label)
                        col_name = f"motivo_{sanitized}"
                        row[col_name] = val
                        dynamic_columns.add(col_name)

                for (d, label), val in status_metrics.items():
                    if d == date_str and label != "valid":
                        sanitized = sanitize_dynamic_label(label)
                        col_name = f"erro_{sanitized}"
                        row[col_name] = val
                        dynamic_columns.add(col_name)

                all_rows.append(row)
                rows_added_for_key += 1

            if rows_added_for_key == 0:
                logging.warning(
                    "Nenhuma linha diária de score encontrada para chave %s. Criando linha summary_only.",
                    metadata["site_key"]
                )

                row = build_summary_only_row(
                    metadata,
                    summary_metrics,
                    extraction_timestamp,
                    args.days
                )

                all_rows.append(row)

    if not all_rows:
        logging.error("Nenhum dado encontrado.")
        return

    base_columns = [
        "extraction_timestamp",
        "report_days",
        "record_type",
        "date",

        "project_id",
        "key_name",
        "display_name",
        "site_key",
        "integration_type",
        "top_domain",
        "waf_type",
        "created",

        "consumer_assessments",
        "enterprise_assessments",
        "executes",
        "gcp_assessments",
        "non_gcp_assessments",
        "mobile_sdk_assessments",
        "v2_web_assessments_estimated",
        "v2_pbc_assessments",
        "v3_web_assessments_estimated",
        "challenged_sessions",
        "challenged_sessions_no_assessments",
        "payment_fraud_assessments",
        "smsd_assessments",
        "errors",

        "error_rate",
        "challenge_rate",
        "execute_to_assessment_rate",

        "total_score_evals",
        "threats_score_0_0_to_0_4",
        "legitimate_score_0_5_to_1_0",
        "threat_rate",
        "legitimate_rate",
        "score_low_ratio",
        "score_high_ratio",
    ]

    final_columns = base_columns + SCORE_COLUMNS + sorted(dynamic_columns)

    logging.info("Gravando %s linhas em %s", len(all_rows), args.output)

    with open(args.output, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=final_columns,
            extrasaction="ignore"
        )

        writer.writeheader()

        for row in all_rows:
            for column in final_columns:
                if column not in row:
                    row[column] = 0

            writer.writerow(row)

    logging.info("CSV unificado gerado com sucesso: %s", args.output)
    logging.info("Total de linhas: %s", len(all_rows))


if __name__ == "__main__":
    main()