/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mappings;

import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.AdminClient;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentType;

import java.io.IOException;

public class MapperApplier {

    private final AdminClient client;

    public MapperApplier(AdminClient client) {
        this.client = client;
    }

    public void createMappingAction(String logIndex, String ruleTopic, ActionListener<AcknowledgedResponse> listener) throws IOException {
        PutMappingRequest request = new PutMappingRequest(logIndex)
                .source(MapperFacade.aliasMappings(ruleTopic), XContentType.JSON);

        client.indices().putMapping(request, listener);
    }

    public void updateMappingAction(String logIndex, String ruleTopic, String field, String alias) {

    }

    public void readMappingAction(String logIndex, String ruleTopic) {

    }
}