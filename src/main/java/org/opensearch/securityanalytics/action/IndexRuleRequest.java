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
import org.opensearch.rest.RestRequest;

import java.io.IOException;

public class IndexRuleRequest extends ActionRequest {

    private String ruleId;

    private WriteRequest.RefreshPolicy refreshPolicy;

    private String category;

    private RestRequest.Method method;

    private String rule;

    private Boolean forced;

    public IndexRuleRequest(
            String ruleId,
            WriteRequest.RefreshPolicy refreshPolicy,
            String category,
            RestRequest.Method method,
            String rule,
            Boolean forced
    ) {
        super();
        this.ruleId = ruleId;
        this.refreshPolicy = refreshPolicy;
        this.category = category;
        this.method = method;
        this.rule = rule;
        this.forced = forced;
    }

    public IndexRuleRequest(StreamInput sin) throws IOException {
        this(sin.readString(),
             WriteRequest.RefreshPolicy.readFrom(sin),
             sin.readString(),
             sin.readEnum(RestRequest.Method.class),
             sin.readString(),
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
        out.writeString(category);
        out.writeEnum(method);
        out.writeString(rule);
        out.writeBoolean(forced);
    }

    public String getRuleId() {
        return ruleId;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return refreshPolicy;
    }

    public String getCategory() {
        return category;
    }

    public RestRequest.Method getMethod() {
        return method;
    }

    public String getRule() {
        return rule;
    }

    public Boolean isForced() {
        return forced;
    }
}