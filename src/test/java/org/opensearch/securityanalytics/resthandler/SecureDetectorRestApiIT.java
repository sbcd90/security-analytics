/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.junit.Assert;

import java.util.Map;
import java.io.IOException;

public class SecureDetectorRestApiIT extends SecurityAnalyticsRestTestCase {

    static String DETECTOR_FULL_ACCESS_ROLE = "detector_full_access";
    static String DETECTOR_READ_ACCESS_ROLE = "detector_read_access";
    static String TEST_HR_BACKEND_ROLE = "HR";

    static Map<String, String> roleToPermissionsMap = Map.ofEntries(
            Map.entry(DETECTOR_FULL_ACCESS_ROLE, "cluster:admin/opendistro/securityanalytics/detector/*"),
            Map.entry(DETECTOR_READ_ACCESS_ROLE, "cluster:admin/opendistro/securityanalytics/detector/read")
    );

//    public void testCreateUserTest() throws IOException {
//        String user = "user1";
//        String[] backendRoles = { TEST_HR_BACKEND_ROLE };
//        createUserWithData(user, user, DETECTOR_FULL_ACCESS_ROLE, backendRoles, roleToPermissionsMap.get(DETECTOR_FULL_ACCESS_ROLE) );
//        Assert.assertEquals(1, 1);
//    }

}