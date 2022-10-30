/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.http.HttpHost;
import org.apache.http.HttpStatus;
import org.junit.After;
import org.junit.Before;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.RestClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.rest.SecureRestClientBuilder;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.junit.Assert;
import org.opensearch.securityanalytics.model.Detector;

import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.io.IOException;

import static org.opensearch.securityanalytics.TestHelpers.*;
import static org.opensearch.securityanalytics.TestHelpers.randomDoc;

public class SecureDetectorRestApiIT extends SecurityAnalyticsRestTestCase {

    static String DETECTOR_FULL_ACCESS_ROLE = "detector_full_access";
    static String DETECTOR_READ_ACCESS_ROLE = "detector_read_access";
    static String TEST_HR_BACKEND_ROLE = "HR";

    static Map<String, String> roleToPermissionsMap = Map.ofEntries(
            Map.entry(DETECTOR_FULL_ACCESS_ROLE, "cluster:admin/opendistro/securityanalytics/detector/*"),
            Map.entry(DETECTOR_READ_ACCESS_ROLE, "cluster:admin/opendistro/securityanalytics/detector/read")
    );

    private RestClient userClient;
    private final String user = "userTwo";

    @Before
    public void create() throws IOException {
        createUser(user, user, new String[]{}, new String[]{});
        if (userClient == null) {
            userClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), user, user).setSocketTimeout(60000).build();
        }
    }

    @After
    public void cleanup() throws IOException {
        userClient.close();
        deleteUser(user);
    }

    @SuppressWarnings("unchecked")
    public void testCreatingADetector() throws IOException {
//        createUserRoleMapping("detectors_full_access", user);
        createUserRoleMapping("alerting_full_access", user);
        String index = createTestIndex(client(), randomIndex(), windowsIndexMapping(), Settings.EMPTY);

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"windows\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Detector detector = randomDetector(getRandomPrePackagedRules());

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();
        int createdVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertNotEquals("response is missing Id", Detector.NO_ID, createdId);
        Assert.assertTrue("incorrect version", createdVersion > 0);
        Assert.assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, createdId), createResponse.getHeader("Location"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("rule_topic_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("findings_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("alert_index"));

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);

        String monitorId = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);

        indexDoc(index, "1", randomDoc());

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);
    }

}