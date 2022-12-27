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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class CorrelationInfo implements Writeable, ToXContentObject {

    private String category;

    private String index;

    private List<CorrelationField> fields;

    protected static final String CATEGORY = "category";
    protected static final String INDEX = "index";
    protected static final String CORRELATION_FIELDS = "fields";

    public CorrelationInfo(String category, String index, List<CorrelationField> fields) {
        this.category = category;
        this.index = index;
        this.fields = fields;
    }

    public CorrelationInfo(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readString(),
                sin.readList(CorrelationField::new)
        );
    }

    public Map<String, Object> asTemplateArg() {
        return Map.of(
                CATEGORY, category,
                INDEX, index,
                CORRELATION_FIELDS, fields
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(category);
        out.writeString(index);
        out.writeCollection(fields);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        CorrelationField[] fieldsArray = new CorrelationField[]{};
        fieldsArray = fields.toArray(fieldsArray);

        builder.startObject()
                .field(CATEGORY, category)
                .field(INDEX, index)
                .field(CORRELATION_FIELDS, fieldsArray)
                .endObject();
        return builder;
    }

    public static CorrelationInfo parse(XContentParser xcp) throws IOException {
        String category = null;
        String index = null;
        List<CorrelationField> fields = new ArrayList<>();

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case CATEGORY:
                    category = xcp.text();
                    break;
                case INDEX:
                    index = xcp.textOrNull();
                    break;
                case CORRELATION_FIELDS:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        fields.add(CorrelationField.parse(xcp));
                    }
                    break;
            }
        }
        return new CorrelationInfo(category, index, fields);
    }

    public static CorrelationInfo readFrom(StreamInput sin) throws IOException {
        return new CorrelationInfo(sin);
    }

    public String getCategory() {
        return category;
    }

    public String getIndex() {
        return index;
    }

    public List<CorrelationField> getFields() {
        return fields;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CorrelationInfo that = (CorrelationInfo) o;
        return category.equals(that.category) && index.equals(that.index) && fields.equals(that.fields);
    }

    @Override
    public int hashCode() {
        return Objects.hash(category, index, fields);
    }
}