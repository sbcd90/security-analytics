/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.action.IndexRulesAction;
import org.opensearch.securityanalytics.action.IndexRulesRequest;
import org.opensearch.securityanalytics.action.IndexRulesResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class TransportIndexRulesAction extends HandledTransportAction<IndexRulesRequest, IndexRulesResponse> {

    private static final Logger log = LogManager.getLogger(TransportIndexRulesAction.class);

    private final Client client;

    @Inject
    public TransportIndexRulesAction(TransportService transportService, Client client, ActionFilters actionFilters) {
        super(IndexRulesAction.NAME, transportService, actionFilters, IndexRulesRequest::new);
        this.client = client;
    }

    @Override
    protected void doExecute(Task task, IndexRulesRequest request, ActionListener<IndexRulesResponse> actionListener) {
        log.info("hit securityanalytics");
        actionListener.onResponse(new IndexRulesResponse(RestStatus.CREATED));
    }
}