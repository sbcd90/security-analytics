/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.ValidateActions;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Locale;

public class GetIocFindingsRequest extends ActionRequest {

    private List<String> findingIds;

    private Instant startTime;

    private Instant endTime;

    private String threatIntelMonitorId;

    private Table table;

    public static final String THREAT_INTEL_MONITOR_ID = "monitor_id";

    public GetIocFindingsRequest(String threatIntelMonitorId) {
        super();
        this.threatIntelMonitorId = threatIntelMonitorId;
    }

    public GetIocFindingsRequest(StreamInput sin) throws IOException {
        this(
                sin.readOptionalStringList(),
                sin.readOptionalInstant(),
                sin.readOptionalInstant(),
                sin.readOptionalString(),
                Table.readFrom(sin)
        );
    }

    public GetIocFindingsRequest(List<String> findingIds,
                                 Instant startTime,
                                 Instant endTime,
                                 String threatIntelMonitorId,
                                 Table table) {
        this.findingIds = findingIds;
        this.startTime = startTime;
        this.endTime = endTime;
        this.threatIntelMonitorId = threatIntelMonitorId;
        this.table = table;
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (threatIntelMonitorId != null && threatIntelMonitorId.isEmpty()) {
            validationException = ValidateActions.addValidationError(String.format(Locale.getDefault(),
                    "threat intel monitor id is missing"), validationException);
        } else if (startTime != null && endTime != null && startTime.isAfter(endTime)) {
            validationException = ValidateActions.addValidationError(String.format(Locale.getDefault(),
                    "startTime should be less than endTime"), validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalStringCollection(findingIds);
        out.writeOptionalInstant(startTime);
        out.writeOptionalInstant(endTime);
        out.writeOptionalString(threatIntelMonitorId);
        table.writeTo(out);
    }

    public List<String> getFindingIds() {
        return findingIds;
    }

    public Instant getStartTime() {
        return startTime;
    }

    public Instant getEndTime() {
        return endTime;
    }

    public String getThreatIntelMonitorId() {
        return threatIntelMonitorId;
    }

    public Table getTable() {
        return table;
    }
}