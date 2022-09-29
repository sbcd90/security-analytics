/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;

import java.io.IOException;

public class DeleteRuleRequest extends ActionRequest {

    private Boolean forced;

    private String ruleId;

    private WriteRequest.RefreshPolicy refreshPolicy;

    public DeleteRuleRequest(String ruleId, WriteRequest.RefreshPolicy refreshPolicy, Boolean forced) {
        super();
        this.ruleId = ruleId;
        this.refreshPolicy = refreshPolicy;
        this.forced = forced;
    }

    public DeleteRuleRequest(StreamInput sin) throws IOException {
        this(sin.readString(),
             WriteRequest.RefreshPolicy.readFrom(sin),
             sin.readBoolean());
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(ruleId);
        refreshPolicy.writeTo(out);
        out.writeBoolean(forced);
    }

    public String getRuleId() {
        return ruleId;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return refreshPolicy;
    }

    public Boolean isForced() {
        return forced;
    }
}