/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.client.AdminClient;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.health.ClusterIndexHealth;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.routing.IndexRoutingTable;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Objects;

public class CorrelationIndices {

    private static final Logger log = LogManager.getLogger(CorrelationIndices.class);
    public static final String CORRELATION_INDEX = ".opensearch-sap-correlation-config";
    public static final long FIXED_HISTORICAL_INTERVAL = 24L * 60L * 60L * 20L * 1000L;

    private final AdminClient client;

    private final ClusterService clusterService;

    public CorrelationIndices(AdminClient client, ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
    }

    public static String correlationMappings() throws IOException {
        return new String(Objects.requireNonNull(CorrelationIndices.class.getClassLoader().getResourceAsStream("mappings/correlation.json")).readAllBytes(), Charset.defaultCharset());
    }

    public void initCorrelationIndex(ActionListener<CreateIndexResponse> actionListener) throws IOException {
        if (!correlationIndexExists()) {
            CreateIndexRequest indexRequest = new CreateIndexRequest(CORRELATION_INDEX)
                    .mapping(correlationMappings())
                    .settings(Settings.builder().put("index.hidden", true).put("number_of_shards", 20).put("index.correlation", true).build());
            client.indices().create(indexRequest, actionListener);
        }
    }

    public boolean correlationIndexExists() {
        ClusterState clusterState = clusterService.state();
        return clusterState.getRoutingTable().hasIndex(CORRELATION_INDEX);
    }

    public ClusterIndexHealth correlationIndexHealth() {
        ClusterIndexHealth indexHealth = null;

        if (correlationIndexExists()) {
            IndexRoutingTable indexRoutingTable = clusterService.state().routingTable().index(CORRELATION_INDEX);
            IndexMetadata indexMetadata = clusterService.state().metadata().index(CORRELATION_INDEX);

            indexHealth = new ClusterIndexHealth(indexMetadata, indexRoutingTable);
        }
        return indexHealth;
    }
}