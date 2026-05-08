#!/usr/bin/env python3

import csv
import argparse
import logging
from datetime import datetime, timedelta, timezone

from google.cloud import recaptchaenterprise_v1
from google.cloud import monitoring_v3
from google.protobuf import timestamp_pb2
from google.api_core.exceptions import GoogleAPICallError, PermissionDenied, NotFound


DEFAULT_PROJECTS = [
    "recaptcha-bradesco-corportivo",
    "recaptcha-bradesco-corprtivo2"
]


SCORE_COLUMNS = [
    "score_0.0", "score_0.1", "score_0.2", "score_0.3", "score_0.4",
    "score_0.5", "score_0.6", "score_0.7", "score_0.8", "score_0.9", "score_1.0",
]


REASON_COLUMNS = [
    "motivo_indefinido",
    "motivo_profile_match",
    "motivo_suspicious_login_activity",
    "motivo_suspicious_account_creation",
    "motivo_related_accounts_number_high",
]


ERROR_COLUMNS = [
    "erro_indefinido",
    "erro_invalid",
    "erro_expired",
    "erro_dupe",
    "erro_missing",
    "erro_malformed",
    "erro_browser_error",
    "erro_unknown_invalid_reason",
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

    safe_chars = []
    for ch in normalized:
        if ch.isalnum() or ch == "_":
            safe_chars.append(ch)
        else:
            safe_chars.append("_")

    normalized = "".join(safe_chars)

    while "__" in normalized:
        normalized = normalized.replace("__", "_")

    normalized = normalized.strip("_")

    return normalized or "indefinido"


def get_value(data, snake_key, camel_key=None, default=None):
    if not isinstance(data, dict):
        return default

    if snake_key in data:
        return data.get(snake_key, default)

    if camel_key and camel_key in data:
        return data.get(camel_key, default)

    return default


def parse_datetime(value):
    if not value:
        return None

    if isinstance(value, datetime):
        return value

    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed

    except Exception:
        return None


def get_date_range(days):
    today = datetime.now(timezone.utc).date()
    start_date = today - timedelta(days=days - 1)

    return [
        (start_date + timedelta(days=i)).strftime("%Y-%m-%d")
        for i in range(days)
    ]


def get_protection_model(integration_type):
    if integration_type in ["CHECKBOX", "INVISIBLE"]:
        return "CHALLENGE"

    if integration_type == "SCORE":
        return "SCORE_BASED"

    if integration_type == "MOBILE":
        return "MOBILE"

    return "OTHER"


def get_key_metadata(key, project_id):
    key_name = key.name
    site_key = key_name.split("/")[-1]

    display_name = getattr(key, "display_name", "")
    create_time = proto_datetime_to_string(getattr(key, "create_time", None))
    created_dt = parse_datetime(create_time)

    key_age_days = 0
    if created_dt:
        key_age_days = (datetime.now(timezone.utc) - created_dt).days

    labels = dict(getattr(key, "labels", {}))

    allowed_domains = []
    top_domain = "N/A"

    try:
        if key.web_settings and key.web_settings.allowed_domains:
            allowed_domains = list(key.web_settings.allowed_domains)
            top_domain = allowed_domains[0] if allowed_domains else "N/A"
    except Exception as e:
        logging.warning("Falha ao extrair allowed_domains da chave %s: %s", key_name, e)

    integration_type = "N/A"
    waf_type = "NONE"

    try:
        if key.web_settings:
            integration_type = enum_to_string(key.web_settings.integration_type)
        elif key.android_settings or key.ios_settings:
            integration_type = "MOBILE"
    except Exception as e:
        logging.warning("Falha ao extrair tipo de integração da chave %s: %s", key_name, e)

    try:
        if key.waf_settings:
            waf_type = enum_to_string(key.waf_settings.waf_feature)
    except Exception as e:
        logging.warning("Falha ao extrair waf_settings da chave %s: %s", key_name, e)

    protection_model = get_protection_model(integration_type)

    return {
        "project_id": project_id,
        "key_name": key_name,
        "display_name": display_name,
        "site_key": site_key,
        "integration_type": integration_type,
        "protection_model": protection_model,
        "top_domain": top_domain,
        "allowed_domains": ",".join(allowed_domains) if allowed_domains else "N/A",
        "waf_type": waf_type,
        "created": create_time,
        "key_age_days": key_age_days,
        "labels": ";".join([f"{k}={v}" for k, v in labels.items()]) if labels else "N/A",
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
        if hasattr(point.value, "distribution_value") and point.value.distribution_value.count:
            return int(point.value.distribution_value.count)
    except Exception:
        pass

    try:
        return int(point.value.double_value or point.value.int64_value or 0)
    except Exception:
        return 0


def query_metric_daily_sum(client, project_id, metric_type, key_id, days_back, extra_filter=""):
    project_name = f"projects/{project_id}"
    interval = build_interval(days_back)

    filter_str = f'metric.type = "{metric_type}" AND resource.labels.key_id = "{key_id}"'

    if extra_filter:
        filter_str += f" AND ({extra_filter})"

    aggregation = monitoring_v3.Aggregation({
        "alignment_period": timedelta(days=1),
        "per_series_aligner": monitoring_v3.Aggregation.Aligner.ALIGN_SUM,
        "cross_series_reducer": monitoring_v3.Aggregation.Reducer.REDUCE_SUM,
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
            for point in series.points:
                date_str = point.interval.end_time.strftime("%Y-%m-%d")
                val = read_point_value(point)
                results_dict[date_str] = results_dict.get(date_str, 0) + val

        return results_dict

    except PermissionDenied as e:
        logging.error(
            "Permissão negada ao consultar métrica diária %s no projeto %s / key %s: %s",
            metric_type, project_id, key_id, e
        )
        return {}

    except NotFound as e:
        logging.error(
            "Métrica/projeto não encontrado: %s | projeto=%s | key=%s | erro=%s",
            metric_type, project_id, key_id, e
        )
        return {}

    except GoogleAPICallError as e:
        logging.error(
            "Erro Google API ao consultar métrica diária %s no projeto %s / key %s: %s",
            metric_type, project_id, key_id, e
        )
        return {}

    except Exception as e:
        logging.exception(
            "Erro inesperado ao consultar métrica diária %s no projeto %s / key %s: %s",
            metric_type, project_id, key_id, e
        )
        return {}


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
            label_val = (
                series.metric.labels.get("reason")
                or series.metric.labels.get("label")
                or series.metric.labels.get("token_status")
                or series.metric.labels.get("challenge")
                or "indefinido"
            )

            for point in series.points:
                date_str = point.interval.end_time.strftime("%Y-%m-%d")
                val = read_point_value(point)

                key = (date_str, label_val)
                results_dict[key] = results_dict.get(key, 0) + val

        return results_dict

    except PermissionDenied as e:
        logging.error(
            "Permissão negada ao consultar labels da métrica %s no projeto %s / key %s: %s",
            metric_type, project_id, key_id, e
        )
        return {}

    except NotFound as e:
        logging.error(
            "Métrica/projeto não encontrado ao consultar labels: %s | projeto=%s | key=%s | erro=%s",
            metric_type, project_id, key_id, e
        )
        return {}

    except GoogleAPICallError as e:
        logging.error(
            "Erro Google API ao consultar labels da métrica %s no projeto %s / key %s: %s",
            metric_type, project_id, key_id, e
        )
        return {}

    except Exception as e:
        logging.exception(
            "Erro inesperado ao consultar labels da métrica %s no projeto %s / key %s: %s",
            metric_type, project_id, key_id, e
        )
        return {}


def get_sdk_metrics(recaptcha_client, key_name):
    try:
        request = recaptchaenterprise_v1.GetMetricsRequest(
            name=f"{key_name}/metrics"
        )

        metrics_pb = recaptcha_client.get_metrics(request=request)
        return recaptchaenterprise_v1.Metrics.to_dict(metrics_pb)

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


def extract_score_metrics_by_date(sdk_metrics):
    score_by_date = {}

    score_metrics = get_value(sdk_metrics, "score_metrics", "scoreMetrics", [])
    start_time_raw = get_value(sdk_metrics, "start_time", "startTime", "")

    base_date = parse_datetime(start_time_raw)

    if not base_date:
        base_date = datetime.now(timezone.utc) - timedelta(days=90)

    for i, day_data in enumerate(score_metrics):
        dt_obj = base_date + timedelta(days=i)
        date_str = dt_obj.strftime("%Y-%m-%d")

        overall_metrics = get_value(day_data, "overall_metrics", "overallMetrics", {})
        buckets = get_value(overall_metrics, "score_buckets", "scoreBuckets", {})

        normalized_buckets = {}
        for k, v in (buckets or {}).items():
            normalized_buckets[str(k)] = v

        score_by_date[date_str] = normalized_buckets

    return score_by_date


def extract_challenge_metrics_by_date(sdk_metrics):
    challenge_by_date = {}

    challenge_metrics_list = get_value(sdk_metrics, "challenge_metrics", "challengeMetrics", [])
    start_time_raw = get_value(sdk_metrics, "start_time", "startTime", "")

    base_date = parse_datetime(start_time_raw)

    if not base_date:
        base_date = datetime.now(timezone.utc) - timedelta(days=90)

    for i, day_data in enumerate(challenge_metrics_list):
        dt_obj = base_date + timedelta(days=i)
        date_str = dt_obj.strftime("%Y-%m-%d")

        challenge_by_date[date_str] = {
            "pageload_count": get_value(day_data, "pageload_count", "pageloadCount", 0),
            "nocaptcha_count": get_value(day_data, "nocaptcha_count", "nocaptchaCount", 0),
            "failed_count": get_value(day_data, "failed_count", "failedCount", 0),
            "passed_count": get_value(day_data, "passed_count", "passedCount", 0),
        }

    return challenge_by_date


def build_daily_metrics(monitoring_client, project_id, site_key, days):
    m_assess_labels = "recaptchaenterprise.googleapis.com/assessments"
    m_assess_count = "recaptchaenterprise.googleapis.com/assessment_count"
    m_exec = "recaptchaenterprise.googleapis.com/executes"
    m_sms = "recaptchaenterprise.googleapis.com/sms_toll_fraud_risks"

    return {
        "enterprise_assessments": query_metric_daily_sum(
            monitoring_client, project_id, m_assess_count, site_key, days
        ),
        "executes": query_metric_daily_sum(
            monitoring_client, project_id, m_exec, site_key, days
        ),
        "gcp_assessments": query_metric_daily_sum(
            monitoring_client, project_id, m_assess_labels, site_key, days,
            'metric.labels.platform = "web"'
        ),
        "non_gcp_assessments": query_metric_daily_sum(
            monitoring_client, project_id, m_assess_labels, site_key, days,
            'metric.labels.platform != "web"'
        ),
        "mobile_sdk_assessments": query_metric_daily_sum(
            monitoring_client, project_id, m_assess_labels, site_key, days,
            'metric.labels.platform = "android" OR metric.labels.platform = "ios"'
        ),
        "challenged_sessions": query_metric_daily_sum(
            monitoring_client, project_id, m_assess_labels, site_key, days,
            'metric.labels.challenge = "challenge"'
        ),
        "smsd_assessments": query_metric_daily_sum(
            monitoring_client, project_id, m_sms, site_key, days
        ),
        "errors": query_metric_daily_sum(
            monitoring_client, project_id, m_assess_count, site_key, days,
            'metric.labels.token_status != "valid"'
        ),
    }


def get_daily_value(metrics_by_name, metric_name, date_str):
    metric = metrics_by_name.get(metric_name, {})
    return int(metric.get(date_str, 0) or 0)


def build_daily_row(
    metadata,
    daily_metrics,
    date_str,
    score_buckets,
    challenge_data,
    defender_metrics,
    status_metrics,
    extraction_timestamp,
    days
):
    integration_type = metadata.get("integration_type", "N/A")
    protection_model = metadata.get("protection_model", "OTHER")

    enterprise_assessments = get_daily_value(daily_metrics, "enterprise_assessments", date_str)
    executes = get_daily_value(daily_metrics, "executes", date_str)
    gcp_assessments = get_daily_value(daily_metrics, "gcp_assessments", date_str)
    non_gcp_assessments = get_daily_value(daily_metrics, "non_gcp_assessments", date_str)
    mobile_sdk_assessments = get_daily_value(daily_metrics, "mobile_sdk_assessments", date_str)
    challenged_sessions = get_daily_value(daily_metrics, "challenged_sessions", date_str)
    smsd_assessments = get_daily_value(daily_metrics, "smsd_assessments", date_str)
    errors = get_daily_value(daily_metrics, "errors", date_str)

    row = dict(metadata)

    row.update({
        "extraction_timestamp": extraction_timestamp,
        "report_days": days,
        "record_type": "daily_key_metric",
        "date": date_str,

        "protection_model": protection_model,

        "consumer_assessments": 0,
        "enterprise_assessments": enterprise_assessments,
        "total_assessments": enterprise_assessments,

        "executes": executes,
        "gcp_assessments": gcp_assessments,
        "non_gcp_assessments": non_gcp_assessments,
        "mobile_sdk_assessments": mobile_sdk_assessments,

        "v2_web_assessments_estimated": enterprise_assessments if integration_type in ["CHECKBOX", "INVISIBLE"] else 0,

        # Placeholder mantido por compatibilidade histórica.
        # Legacy / Private Beta Captcha. Não representa dado real nesta versão.
        "v2_pbc_assessments": 0,

        "v3_web_assessments_estimated": enterprise_assessments if integration_type == "SCORE" else 0,

        "challenged_sessions": challenged_sessions,

        # Placeholder mantido para evolução futura.
        # Futuro: calcular sessões desafiadas sem assessment quando houver label/métrica confiável.
        "challenged_sessions_no_assessments": 0,

        # Placeholder mantido para evolução futura.
        # Requer uso de Transaction Events / Fraud Prevention.
        "payment_fraud_assessments": 0,

        "smsd_assessments": smsd_assessments,
        "errors": errors,

        "error_rate": safe_divide(errors, enterprise_assessments),
        "challenge_rate": safe_divide(challenged_sessions, enterprise_assessments),
        "execute_to_assessment_rate": safe_divide(executes, enterprise_assessments),

        "estimated_v2_volume": enterprise_assessments if integration_type in ["CHECKBOX", "INVISIBLE"] else 0,
        "estimated_v3_volume": enterprise_assessments if integration_type == "SCORE" else 0,
    })

    ch = challenge_data.get(date_str, {})

    challenge_pageload = int(ch.get("pageload_count", 0) or 0)
    challenge_nocaptcha = int(ch.get("nocaptcha_count", 0) or 0)
    challenge_passed = int(ch.get("passed_count", 0) or 0)
    challenge_failed = int(ch.get("failed_count", 0) or 0)

    row.update({
        "challenge_pageload": challenge_pageload,
        "challenge_nocaptcha": challenge_nocaptcha,
        "challenge_passed": challenge_passed,
        "challenge_failed": challenge_failed,
        "challenge_pass_rate": safe_divide(challenge_passed, challenge_pageload),
        "challenge_failed_rate": safe_divide(challenge_failed, challenge_pageload),
    })

    for col in SCORE_COLUMNS:
        bucket_key = col.replace("score_", "").replace(".", "")
        row[col] = int(score_buckets.get(bucket_key, 0) or 0)

    threats = sum(
        int(score_buckets.get(s, 0) or 0)
        for s in ["0", "10", "20", "30", "40"]
    )

    legitimate = sum(
        int(score_buckets.get(s, 0) or 0)
        for s in ["50", "60", "70", "80", "90", "100"]
    )

    total_score = threats + legitimate

    row.update({
        "total_score_evals": total_score,
        "threats_score_0_0_to_0_4": threats,
        "legitimate_score_0_5_to_1_0": legitimate,
        "threat_rate": safe_divide(threats, total_score),
        "legitimate_rate": safe_divide(legitimate, total_score),
        "score_low_ratio": safe_divide(threats, total_score),
        "score_high_ratio": safe_divide(legitimate, total_score),
    })

    for (d, label), val in defender_metrics.items():
        if d == date_str:
            col_name = f"motivo_{sanitize_dynamic_label(label)}"
            row[col_name] = val

    for (d, label), val in status_metrics.items():
        if d == date_str and label != "valid":
            col_name = f"erro_{sanitize_dynamic_label(label)}"
            row[col_name] = val

    return row


def main():
    parser = argparse.ArgumentParser(
        description="SegAplic Google reCAPTCHA Enterprise - Relatório de Maturidade"
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
        help="Dias de histórico"
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Habilita logs em modo debug"
    )

    args = parser.parse_args()

    setup_logging(args.debug)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    inventory_file = f"recaptcha_inventory_{timestamp}.csv"
    metrics_file = f"recaptcha_metrics_{timestamp}.csv"

    logging.info("Iniciando extração reCAPTCHA Enterprise / Google Cloud Fraud Defense")
    logging.info("Projetos: %s", args.projects)
    logging.info("Período: últimos %s dias", args.days)
    logging.info("Arquivos de saída: %s | %s", inventory_file, metrics_file)

    recaptcha_client = recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient()
    monitoring_client = monitoring_v3.MetricServiceClient()

    inventory_rows = []
    metrics_rows = []
    dynamic_columns = set()

    extraction_timestamp = datetime.now(timezone.utc).isoformat()
    date_range = get_date_range(args.days)

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

            sdk_metrics = get_sdk_metrics(
                recaptcha_client,
                metadata["key_name"]
            )

            score_by_date = extract_score_metrics_by_date(sdk_metrics)
            challenge_by_date = extract_challenge_metrics_by_date(sdk_metrics)

            daily_metrics = build_daily_metrics(
                monitoring_client,
                metadata["project_id"],
                metadata["site_key"],
                args.days
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

            total_assessments_last_days = sum(
                get_daily_value(daily_metrics, "enterprise_assessments", d)
                for d in date_range
            )

            inventory_rows.append({
                **metadata,
                "extraction_timestamp": extraction_timestamp,
                "record_type": "key_inventory",
                "report_days": args.days,
                "active_last_days": total_assessments_last_days > 0,
                "total_assessments_last_days": total_assessments_last_days,

                # Chave considerada órfã quando não possui assessments no período definido por --days.
                "is_orphan_key": total_assessments_last_days == 0,
            })

            for date_str in date_range:
                row = build_daily_row(
                    metadata=metadata,
                    daily_metrics=daily_metrics,
                    date_str=date_str,
                    score_buckets=score_by_date.get(date_str, {}),
                    challenge_data=challenge_by_date,
                    defender_metrics=defender_metrics,
                    status_metrics=status_metrics,
                    extraction_timestamp=extraction_timestamp,
                    days=args.days,
                )

                for col in row:
                    if col.startswith(("motivo_", "erro_")):
                        dynamic_columns.add(col)

                metrics_rows.append(row)

    if inventory_rows:
        inventory_columns = [
            "extraction_timestamp",
            "record_type",
            "report_days",
            "active_last_days",
            "total_assessments_last_days",
            "is_orphan_key",

            "project_id",
            "key_name",
            "display_name",
            "site_key",
            "integration_type",
            "protection_model",
            "top_domain",
            "allowed_domains",
            "waf_type",
            "created",
            "key_age_days",
            "labels",
        ]

        with open(inventory_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=inventory_columns,
                extrasaction="ignore"
            )

            writer.writeheader()

            for row in inventory_rows:
                writer.writerow(row)

        logging.info("Inventário gerado: %s (%s chaves)", inventory_file, len(inventory_rows))

    else:
        logging.warning("Nenhuma linha de inventário gerada.")

    if metrics_rows:
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
            "protection_model",
            "top_domain",
            "allowed_domains",
            "waf_type",
            "created",
            "key_age_days",
            "labels",

            "consumer_assessments",
            "enterprise_assessments",
            "total_assessments",
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

            "estimated_v2_volume",
            "estimated_v3_volume",

            "challenge_pageload",
            "challenge_nocaptcha",
            "challenge_passed",
            "challenge_failed",
            "challenge_pass_rate",
            "challenge_failed_rate",

            "total_score_evals",
            "threats_score_0_0_to_0_4",
            "legitimate_score_0_5_to_1_0",
            "threat_rate",
            "legitimate_rate",
            "score_low_ratio",
            "score_high_ratio",
        ]

        known_dynamic_columns = set(REASON_COLUMNS + ERROR_COLUMNS)
        extra_dynamic_columns = sorted(dynamic_columns - known_dynamic_columns)

        final_columns = (
            base_columns
            + SCORE_COLUMNS
            + REASON_COLUMNS
            + ERROR_COLUMNS
            + extra_dynamic_columns
        )

        with open(metrics_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=final_columns,
                extrasaction="ignore"
            )

            writer.writeheader()

            for row in metrics_rows:
                for col in final_columns:
                    if col not in row:
                        row[col] = 0

                writer.writerow(row)

        logging.info("Métricas diárias geradas: %s (%s linhas)", metrics_file, len(metrics_rows))

    else:
        logging.warning("Nenhuma linha de métrica diária gerada.")

    logging.info("Processo finalizado.")
    logging.info("Projetos processados: %s", len(args.projects))
    logging.info("Total de chaves: %s", len(inventory_rows))
    logging.info("Total de linhas de métricas: %s", len(metrics_rows))
    logging.info("Colunas dinâmicas detectadas: %s", len(dynamic_columns))


if __name__ == "__main__":
    main()