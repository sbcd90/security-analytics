/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.commons.alerting.action.PublishAdRequest;
import org.opensearch.commons.alerting.action.SubscribeAdResponse;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.io.stream.InputStreamStreamInput;
import org.opensearch.core.common.io.stream.OutputStreamStreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;


public class TransportAdCallbackAction extends HandledTransportAction<ActionRequest, SubscribeAdResponse> implements SecureTransportAction {

    private static final Logger log = LogManager.getLogger(TransportAdCallbackAction.class);

    private final Client client;

    private final ThreadPool threadPool;

    @Inject
    public TransportAdCallbackAction(TransportService transportService,
                                     Client client,
                                     ActionFilters actionFilters) {
        super("cluster:admin/opensearch/securityanalytics/ad", transportService, actionFilters, PublishAdRequest::new);
        this.client = client;
        this.threadPool = this.client.threadPool();
    }

    @Override
    protected void doExecute(Task task, ActionRequest request, ActionListener<SubscribeAdResponse> listener) {
        User user = readUserFromThreadContext(this.threadPool);
        log.info("hit ad callback-" + user.getName());
        listener.onResponse(new SubscribeAdResponse(RestStatus.ACCEPTED));
    }

    private PublishAdRequest transformRequest(ActionRequest request) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        OutputStreamStreamOutput osso = new OutputStreamStreamOutput(baos);
        request.writeTo(osso);

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        InputStreamStreamInput issi = new InputStreamStreamInput(bais);
        return new PublishAdRequest(issi);
    }
}