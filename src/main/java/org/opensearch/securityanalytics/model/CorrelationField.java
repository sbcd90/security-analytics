/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentParserUtils;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;

public class CorrelationField implements Writeable, ToXContentObject {

    private Boolean isQuery;
    private Map<String, Object> fields;

    protected static final String IS_QUERY_FIELD = "query";
    protected static final String CORRELATION_FIELD = "field";

    public CorrelationField(Boolean isQuery, Map<String, Object> fields) {
        this.isQuery = isQuery;
        this.fields = fields;
    }

    public CorrelationField(StreamInput sin) throws IOException {
        this(sin.readBoolean(),
            sin.readMap()
        );
    }

    public Map<String, Object> asTemplateArg() {
        return Map.of(
                IS_QUERY_FIELD, isQuery,
                CORRELATION_FIELD, fields
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeBoolean(isQuery);
        out.writeMap(fields);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(IS_QUERY_FIELD, isQuery)
                .field(CORRELATION_FIELD, fields)
                .endObject();
        return builder;
    }

    public static CorrelationField parse(XContentParser xcp) throws IOException {
        Boolean isQuery = null;
        Map<String, Object> fields = null;

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case IS_QUERY_FIELD:
                    isQuery = xcp.booleanValue();
                    break;
                case CORRELATION_FIELD:
                    fields = xcp.map();
                    break;
            }
        }
        return new CorrelationField(isQuery, fields);
    }

    public static CorrelationField readFrom(StreamInput sin) throws IOException {
        return new CorrelationField(sin);
    }

    public Boolean getQuery() {
        return isQuery;
    }

    public Map<String, Object> getFields() {
        return fields;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CorrelationField that = (CorrelationField) o;
        return isQuery.equals(that.isQuery) && fields.equals(that.fields);
    }

    @Override
    public int hashCode() {
        return Objects.hash(isQuery, fields);
    }
}