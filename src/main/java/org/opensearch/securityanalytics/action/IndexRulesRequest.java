/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.rest.RestRequest;

import java.io.IOException;

public class IndexRulesRequest extends ActionRequest {

    private RestRequest.Method method;

    public IndexRulesRequest(RestRequest.Method method) {
        super();
        this.method = method;
    }

    public IndexRulesRequest(StreamInput sin) throws IOException {
        this(sin.readEnum(RestRequest.Method.class));
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeEnum(method);
    }

    public RestRequest.Method getMethod() {
        return method;
    }
}