/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import org.opensearch.client.node.NodeClient;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.GetFindingsAction;
import org.opensearch.securityanalytics.action.GetFindingsRequest;
import org.opensearch.securityanalytics.model.Detector;


import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.GET;

public class RestGetFindingsAction extends BaseRestHandler {

    @Override
    public String getName() {
        return "get_findings_action_sa";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

        String detectorId = request.param("detector_id", null);
        String detectorType = request.param("detectorType", null);
        // Table params
        String sortString = request.param("sortString", "id");
        String sortOrder = request.param("sortOrder", "asc");
        String missing = request.param("missing");
        int size = request.paramAsInt("size", 20);
        int startIndex = request.paramAsInt("startIndex", 0);
        String searchString = request.param("searchString", "");
        String severity = request.param("severity", null);
        String detectionType = request.param("detectionType", null);
        List<String> findingIds = null;
        if (request.param("findingIds") != null) {
            findingIds = Arrays.asList(request.param("findingIds").split(","));
        }
        Instant startTime = null;
        if (request.param("startTime") != null) {
            startTime = Instant.parse(request.param("startTime"));
        }
        Instant endTime= null;
        if (request.param("endTime") != null) {
            endTime = Instant.parse(request.param("endTime"));
        }

        Table table = new Table(
                sortOrder,
                sortString,
                missing,
                size,
                startIndex,
                searchString
        );

        GetFindingsRequest req = new GetFindingsRequest(
                detectorId,
                detectorType,
                table,
                severity,
                detectionType,
                findingIds,
                startTime,
                endTime
        );

        return channel -> client.execute(
                GetFindingsAction.INSTANCE,
                req,
                new RestToXContentListener<>(channel)
        );
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(GET, SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search"));
    }
}
