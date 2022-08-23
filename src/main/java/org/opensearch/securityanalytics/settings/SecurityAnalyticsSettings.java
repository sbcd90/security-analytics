package org.opensearch.securityanalytics.settings;

import org.opensearch.common.settings.Setting;
import org.opensearch.common.unit.TimeValue;

public class SecurityAnalyticsSettings {

    public static Setting<TimeValue> INDEX_TIMEOUT = Setting.positiveTimeSetting("plugins.alerting.index_timeout",
            TimeValue.timeValueSeconds(60),
            Setting.Property.NodeScope, Setting.Property.Dynamic);
}