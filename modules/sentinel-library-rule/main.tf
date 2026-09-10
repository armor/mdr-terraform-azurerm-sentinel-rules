terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.54"
    }
  }
}

locals {
  rule_data                = yamldecode(var.rule)
  path_elements            = split("/", var.path)
  rule_name                = element(local.path_elements, length(local.path_elements) - 1)
  create_incident          = try(lookup(local.rule_data["incidentConfiguration"], "createIncident", false), false)
  create_incident_grouping = try(lookup(local.rule_data["incidentConfiguration"], "grouping", {}), {})
  entity_mappings          = try(lookup(local.rule_data, "entityMappings", []), [])
  techniques               = try(local.rule_data["techniques"] == null ? [] : local.rule_data["techniques"], [])

  # eventGroupingSettings.aggregationKind: SingleAlert (Sentinel default) or AlertPerResult.
  event_grouping_aggregation = try(local.rule_data["eventGroupingSettings"]["aggregationKind"], null)

  # alertDetailsOverride: every field is optional. Content marks "not set" with an
  # empty value (e.g. `alertSeverityColumnName:` with nothing after it), which the
  # provider rejects (StringIsNotEmpty), so blank strings and nulls collapse to null.
  alert_details_override        = try(local.rule_data["alertDetailsOverride"], null)
  override_display_name_format  = try(length(local.alert_details_override["alertDisplayNameFormat"]) > 0 ? local.alert_details_override["alertDisplayNameFormat"] : null, null)
  override_description_format   = try(length(local.alert_details_override["alertDescriptionFormat"]) > 0 ? local.alert_details_override["alertDescriptionFormat"] : null, null)
  override_severity_column_name = try(length(local.alert_details_override["alertSeverityColumnName"]) > 0 ? local.alert_details_override["alertSeverityColumnName"] : null, null)
  override_tactics_column_name  = try(length(local.alert_details_override["alertTacticsColumnName"]) > 0 ? local.alert_details_override["alertTacticsColumnName"] : null, null)
  override_dynamic_properties   = try(local.alert_details_override["alertDynamicProperties"] == null ? [] : local.alert_details_override["alertDynamicProperties"], [])
  has_alert_details_override = anytrue([
    local.override_display_name_format != null,
    local.override_description_format != null,
    local.override_severity_column_name != null,
    local.override_tactics_column_name != null,
    length(local.override_dynamic_properties) > 0,
  ])
}

resource "azurerm_sentinel_alert_rule_scheduled" "rule" {
  name                       = local.rule_name
  log_analytics_workspace_id = var.log_analytics_workspace_id
  display_name               = lookup(local.rule_data, "displayName", local.rule_name)
  severity                   = title(local.rule_data["severity"])
  query                      = local.rule_data["query"]
  tactics                    = lookup(local.rule_data, "tactics", [])
  techniques                 = local.techniques # Full IDs including sub-techniques, e.g. 'T1059.001'.
  description                = lookup(local.rule_data, "description", local.rule_name)
  enabled                    = lookup(local.rule_data, "enabled", true)
  query_frequency            = length(regexall(".*[Dd]$", local.rule_data["queryFrequency"])) > 0 ? "P${upper(local.rule_data["queryFrequency"])}T0H" : "PT${upper(local.rule_data["queryFrequency"])}"
  query_period               = length(regexall(".*[Dd]$", local.rule_data["queryPeriod"])) > 0 ? "P${upper(local.rule_data["queryPeriod"])}T0H" : "PT${upper(local.rule_data["queryPeriod"])}"
  suppression_duration       = try(local.rule_data["suppressionEnabled"] == true ? length(regexall(".*[YyMmDd]$", local.rule_data["suppressionDuration"])) > 0 ? "P${upper(local.rule_data["suppressionDuration"])}T0H" : "PT${upper(local.rule_data["suppressionDuration"])}" : null, null)
  suppression_enabled        = lookup(local.rule_data, "suppressionEnabled", false)
  trigger_operator           = local.rule_data["triggerOperator"] == "gt" ? "GreaterThan" : local.rule_data["triggerOperator"] == "lt" ? "LessThan" : local.rule_data["triggerOperator"]
  trigger_threshold          = local.rule_data["triggerThreshold"]
  custom_details             = try(lookup(local.rule_data, "customDetails", {}), {})

  dynamic "event_grouping" {
    for_each = local.event_grouping_aggregation == null ? [] : [local.event_grouping_aggregation]
    content {
      aggregation_method = event_grouping.value
    }
  }

  dynamic "alert_details_override" {
    for_each = local.has_alert_details_override ? ["enabled"] : []
    content {
      display_name_format  = local.override_display_name_format
      description_format   = local.override_description_format
      severity_column_name = local.override_severity_column_name
      tactics_column_name  = local.override_tactics_column_name

      dynamic "dynamic_property" {
        for_each = local.override_dynamic_properties
        content {
          name  = dynamic_property.value["alertProperty"]
          value = dynamic_property.value["value"]
        }
      }
    }
  }

  dynamic "incident" {
    for_each = local.create_incident == null ? [] : ["enabled"]
    content {
      create_incident_enabled = local.create_incident
      grouping {
        enabled                 = lookup(local.create_incident_grouping, "enabled", null)
        lookback_duration       = lookup(local.create_incident_grouping, "lookbackDuration", null)
        reopen_closed_incidents = lookup(local.create_incident_grouping, "reopenClosedIncidents", null)
        entity_matching_method  = lookup(local.create_incident_grouping, "entityMatchingMethod", "AnyAlert")
        by_entities             = lookup(local.create_incident_grouping, "groupByEntities", [])
        by_alert_details        = lookup(local.create_incident_grouping, "groupByAlertDetails", [])
        by_custom_details       = lookup(local.create_incident_grouping, "groupByCustomDetails", [])
      }
    }
  }

  dynamic "entity_mapping" {
    for_each = local.entity_mappings == null ? [] : local.entity_mappings
    content {
      entity_type = entity_mapping.value["entityType"]
      dynamic "field_mapping" {
        for_each = entity_mapping.value["fieldMappings"]
        content {
          identifier  = field_mapping.value["identifier"]
          column_name = field_mapping.value["columnName"]
        }
      }
    }
  }
}
