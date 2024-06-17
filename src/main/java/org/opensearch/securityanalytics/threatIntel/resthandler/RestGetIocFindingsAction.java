/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.resthandler;

import org.opensearch.client.node.NodeClient;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.GetFindingsAction;
import org.opensearch.securityanalytics.threatIntel.action.GetIocFindingsRequest;

import java.io.IOException;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.GET;

public class RestGetIocFindingsAction extends BaseRestHandler {

    @Override
    public String getName() {
        return "get_ioc_findings_action_sa";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        String threatIntelMonitorId = request.param("monitor_id");

        String sortString = request.param("sortString", "timestamp");
        String sortOrder = request.param("sortOrder", "asc");
        String missing = request.param("missing");
        int size = request.paramAsInt("size", 20);
        int startIndex = request.paramAsInt("startIndex", 0);
        String searchString = request.param("searchString", "");

        List<String> findingIds = null;
        if (request.param("findingIds") != null) {
            findingIds = Arrays.asList(request.param("findingIds").split(","));
        }
        Instant startTime = null;
        String startTimeParam = request.param("startTime");
        if (startTimeParam != null && !startTimeParam.isEmpty()) {
            try {
                startTime = Instant.ofEpochMilli(Long.parseLong(startTimeParam));
            } catch (NumberFormatException | NullPointerException | DateTimeException e) {
                // Handle the parsing error
                // For example, log the error or provide a default value
                startTime = Instant.now(); // Default value or fallback
            }
        }

        Instant endTime = null;
        String endTimeParam = request.param("endTime");
        if (endTimeParam != null && !endTimeParam.isEmpty()) {
            try {
                endTime = Instant.ofEpochMilli(Long.parseLong(endTimeParam));
            } catch (NumberFormatException | NullPointerException | DateTimeException e) {
                // Handle the parsing error
                // For example, log the error or provide a default value
                endTime = Instant.now(); // Default value or fallback
            }
        }

        Table table = new Table(
                sortOrder,
                sortString,
                missing,
                size,
                startIndex,
                searchString
        );

        GetIocFindingsRequest getIocFindingsRequest = new GetIocFindingsRequest(
                findingIds,
                startTime,
                endTime,
                threatIntelMonitorId,
                table
        );
        return channel -> client.execute(
                GetFindingsAction.INSTANCE,
                getIocFindingsRequest,
                new RestToXContentListener<>(channel)
        );
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(GET, SecurityAnalyticsPlugin.IOC_BASE_URI  + "/findings" + "/_search"));
    }
}

