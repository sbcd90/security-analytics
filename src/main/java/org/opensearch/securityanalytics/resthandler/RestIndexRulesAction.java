/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.rest.*;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.IndexRulesAction;
import org.opensearch.securityanalytics.action.IndexRulesRequest;
import org.opensearch.securityanalytics.action.IndexRulesResponse;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

public class RestIndexRulesAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestIndexRulesAction.class);

    @Override
    public String getName() {
        return "index_rules_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(RestRequest.Method.POST, SecurityAnalyticsPlugin.RULES_BASE_URI));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.getDefault(), "%s %s", request.method(), SecurityAnalyticsPlugin.RULES_BASE_URI));

        IndexRulesRequest indexRulesRequest = new IndexRulesRequest(request.method());
        return new RestChannelConsumer() {
            @Override
            public void accept(RestChannel channel) throws Exception {
                client.execute(IndexRulesAction.INSTANCE, indexRulesRequest, indexRulesResponse(channel, request.method()));
            }
        };
    }

    private RestResponseListener<IndexRulesResponse> indexRulesResponse(RestChannel channel, RestRequest.Method restMethod) {
        return new RestResponseListener<IndexRulesResponse>(channel) {
            @Override
            public RestResponse buildResponse(IndexRulesResponse response) throws Exception {
                RestStatus returnStatus = RestStatus.CREATED;

                RestResponse restResponse = new BytesRestResponse(returnStatus, response.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS));
                return restResponse;
            }
        };
    }
}