/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import org.opensearch.action.ActionListener;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.IndicesAdminClient;
import org.opensearch.cluster.ClusterState;

public class IndexUtils {

    public static Boolean detectorIndexUpdated = false;

    public static void detectorIndexUpdated() {
        detectorIndexUpdated = true;
    }

    public static void updateIndexMapping(
            String index,
            String mapping,
            ClusterState clusterState,
            IndicesAdminClient client,
            ActionListener<AcknowledgedResponse> actionListener
    ) {

    }
}