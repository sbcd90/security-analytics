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

public class CorrelatedIndex implements Writeable, ToXContentObject {

    private String index;

    private List<CorrelationInfo> correlationInfos;

    protected static final String CORRELATION_INDICES = "corr_indices";
    protected static final String INDEX = "index";
    protected static final String CORRELATION_INFOS = "correlate";

    public CorrelatedIndex(String index, List<CorrelationInfo> correlationInfos) {
        this.index = index;
        this.correlationInfos = correlationInfos;
    }

    public CorrelatedIndex(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readList(CorrelationInfo::new)
        );
    }

    public Map<String, Object> asTemplateArg() {
        return Map.of(
                INDEX, index,
                CORRELATION_INFOS, correlationInfos
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(index);
        out.writeCollection(correlationInfos);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        CorrelationInfo[] correlationInfoArray = new CorrelationInfo[]{};
        correlationInfoArray = correlationInfos.toArray(correlationInfoArray);

        builder.startObject()
                .startObject(CORRELATION_INDICES)
                .field(INDEX, index)
                .field(CORRELATION_INFOS, correlationInfoArray)
                .endObject()
                .endObject();
        return builder;
    }

    public static CorrelatedIndex parse(XContentParser xcp) throws IOException {
        String index = null;
        List<CorrelationInfo> correlationInfos = new ArrayList<>();

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.FIELD_NAME, xcp.nextToken(), xcp);
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case INDEX:
                    index = xcp.text();
                    break;
                case CORRELATION_INFOS:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        correlationInfos.add(CorrelationInfo.parse(xcp));
                    }
                    break;
            }
        }
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.END_OBJECT, xcp.nextToken(), xcp);
        return new CorrelatedIndex(index, correlationInfos);
    }

    public String getIndex() {
        return index;
    }

    public List<CorrelationInfo> getCorrelationInfos() {
        return correlationInfos;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CorrelatedIndex that = (CorrelatedIndex) o;
        return index.equals(that.index) && correlationInfos.equals(that.correlationInfos);
    }

    @Override
    public int hashCode() {
        return Objects.hash(index, correlationInfos);
    }
}