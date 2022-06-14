/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.junit.Assert;
import org.opensearch.client.Response;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.SecurityAnalyticsIntegTestCase;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

public class RuleRestApiIT extends SecurityAnalyticsIntegTestCase {

    public void testOnboardRules() throws IOException {
        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULES_BASE_URI, Collections.emptyMap(),
                new StringEntity("{}", ContentType.APPLICATION_JSON));

        Assert.assertEquals("Onboard Rules failed", RestStatus.CREATED.getStatus(), response.getStatusLine().getStatusCode());
        Map<String, Object> responseMap = entityAsMap(response);
        Assert.assertEquals( 0, responseMap.size());
    }
}